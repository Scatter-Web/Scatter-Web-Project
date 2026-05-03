#include "tunnel.hpp"
#include <sw/crypto/kdf.hpp>
#include <cbor.h>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <ctime>

namespace sw::anonrouter {

static uint64_t safe_cbor_uint(const cbor_item_t* item) {
    switch (cbor_int_get_width(item)) {
        case CBOR_INT_8:  return cbor_get_uint8(item);
        case CBOR_INT_16: return cbor_get_uint16(item);
        case CBOR_INT_32: return cbor_get_uint32(item);
        case CBOR_INT_64: return cbor_get_uint64(item);
    }
    return 0;
}

using namespace sw::crypto;

// ── hex helper ───────────────────────────────────────────────────────────────

static std::string to_hex(const SessionToken& t) {
    std::ostringstream ss;
    for (uint8_t b : t) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}

// ── Recruitment payload builders ─────────────────────────────────────────────

Bytes build_recruit_in_payload(const SessionToken& session_tok,
                               const std::string&  deliver_to,
                               GuardType           guard_type,
                               uint32_t            ttl_seconds) {
    cbor_item_t* m = cbor_new_definite_map(4);
    cbor_map_add(m, {cbor_build_string("session_token"),
                     cbor_build_bytestring(session_tok.data(), session_tok.size())});
    cbor_map_add(m, {cbor_build_string("deliver_to"),
                     cbor_build_string(deliver_to.c_str())});
    cbor_map_add(m, {cbor_build_string("guard_type"),
                     cbor_build_uint64(static_cast<uint64_t>(guard_type))});
    cbor_map_add(m, {cbor_build_string("ttl"),
                     cbor_build_uint64(ttl_seconds)});

    uint8_t* buf = nullptr; size_t len = 0;
    cbor_serialize_alloc(m, &buf, &len);
    cbor_decref(&m);
    if (!buf) return {};
    Bytes out(buf, buf + len);
    free(buf);
    return out;
}

Bytes build_recruit_out_payload(const SessionToken& session_tok,
                                const std::string&  forward_to,
                                uint32_t            ttl_seconds) {
    cbor_item_t* m = cbor_new_definite_map(3);
    cbor_map_add(m, {cbor_build_string("session_token"),
                     cbor_build_bytestring(session_tok.data(), session_tok.size())});
    cbor_map_add(m, {cbor_build_string("forward_to"),
                     cbor_build_string(forward_to.c_str())});
    cbor_map_add(m, {cbor_build_string("ttl"),
                     cbor_build_uint64(ttl_seconds)});

    uint8_t* buf = nullptr; size_t len = 0;
    cbor_serialize_alloc(m, &buf, &len);
    cbor_decref(&m);
    if (!buf) return {};
    Bytes out(buf, buf + len);
    free(buf);
    return out;
}

RecruitResult parse_recruit_response(const Bytes& payload) {
    RecruitResult r;
    struct cbor_load_result res{};
    cbor_item_t* root = cbor_load(payload.data(), payload.size(), &res);
    if (!root || res.error.code != CBOR_ERR_NONE) {
        if (root) cbor_decref(&root);
        return r;
    }
    if (!cbor_isa_map(root)) { cbor_decref(&root); return r; }

    for (size_t i = 0; i < cbor_map_size(root); ++i) {
        auto pair = cbor_map_handle(root)[i];
        std::string k(reinterpret_cast<char*>(cbor_string_handle(pair.key)),
                      cbor_string_length(pair.key));
        if (k == "ok")
            r.ok = cbor_is_bool(pair.value) && cbor_get_bool(pair.value);
        else if (k == "reason" && cbor_isa_string(pair.value))
            r.reason.assign(reinterpret_cast<char*>(cbor_string_handle(pair.value)),
                            cbor_string_length(pair.value));
        else if (k == "retry_after")
            r.retry_after = static_cast<int64_t>(safe_cbor_uint(pair.value));
        else if (k == "session_token" && cbor_isa_bytestring(pair.value)
                 && cbor_bytestring_length(pair.value) == 32) {
            std::ostringstream ss;
            auto* h = cbor_bytestring_handle(pair.value);
            for (int j = 0; j < 32; ++j)
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)h[j];
            r.session_tok_hex = ss.str();
        }
    }
    cbor_decref(&root);
    return r;
}

static Bytes build_response(const SessionToken& tok, bool ok,
                             const char* reason = nullptr,
                             int64_t retry_after = 0) {
    cbor_item_t* m = cbor_new_definite_map(ok ? 2 : 4);
    cbor_map_add(m, {cbor_build_string("ok"), cbor_build_bool(ok)});
    cbor_map_add(m, {cbor_build_string("session_token"),
                     cbor_build_bytestring(tok.data(), tok.size())});
    if (!ok && reason) {
        cbor_map_add(m, {cbor_build_string("reason"), cbor_build_string(reason)});
        cbor_map_add(m, {cbor_build_string("retry_after"),
                         cbor_build_uint64(static_cast<uint64_t>(retry_after))});
    }
    uint8_t* buf = nullptr; size_t len = 0;
    cbor_serialize_alloc(m, &buf, &len);
    cbor_decref(&m);
    if (!buf) return {};
    Bytes out(buf, buf + len);
    free(buf);
    return out;
}

Bytes build_recruit_ok(const SessionToken& tok)    { return build_response(tok, true); }
Bytes build_recruit_full(const SessionToken& tok)  {
    return build_response(tok, false, "guard_capacity_full");
}
Bytes build_recruit_choked(const SessionToken& tok, int64_t retry_after) {
    return build_response(tok, false, "bandwidth_credit_insufficient", retry_after);
}

// ── TunnelManager ────────────────────────────────────────────────────────────

std::string TunnelManager::tok_key(const SessionToken& t) { return to_hex(t); }

void TunnelManager::add_inbound(const TunnelInfo& info) {
    std::lock_guard lk(mu_);
    tunnels_[tok_key(info.session_tok)] = info;
}

void TunnelManager::add_outbound(const TunnelInfo& info) {
    std::lock_guard lk(mu_);
    tunnels_[tok_key(info.session_tok)] = info;
}

void TunnelManager::remove(const SessionToken& tok) {
    std::lock_guard lk(mu_);
    tunnels_.erase(tok_key(tok));
}

std::optional<TunnelInfo> TunnelManager::lookup(const SessionToken& tok) const {
    std::lock_guard lk(mu_);
    auto it = tunnels_.find(tok_key(tok));
    if (it == tunnels_.end()) return std::nullopt;
    return it->second;
}

void TunnelManager::forward_via_outbound(const SessionToken& out_tok, const Cell& cell) {
    auto info = lookup(out_tok);
    if (!info) return;
    // Send raw cell bytes to the guard endpoint.
    ByteSpan span{cell.data(), cell.size()};
    transport_.send(info->guard_endpoint, span);
    tft_.record_used_from(info->guard_node_id, static_cast<int64_t>(CELL_SIZE));
}

void TunnelManager::on_inbound_cell(const Cell& cell, InboundCb cb) {
    SessionToken tok = cell_session_tok(cell);
    cb(tok, cell);
}

} // namespace sw::anonrouter
