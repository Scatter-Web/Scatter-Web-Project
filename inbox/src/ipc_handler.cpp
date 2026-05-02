#include "ipc_handler.hpp"
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <chrono>
#include <cstring>

namespace sw::inbox {

using namespace sw::ipc;

static std::string req_string(const CborMap& p, const std::string& k) {
    auto it = p.find(k);
    if (it == p.end() || !it->second.is_string())
        throw std::runtime_error("missing param: " + k);
    return it->second.as_string();
}

static Bytes req_bytes(const CborMap& p, const std::string& k) {
    auto it = p.find(k);
    if (it == p.end() || !it->second.is_bytes())
        throw std::runtime_error("missing param: " + k);
    return it->second.as_bytes();
}

static int64_t now_s() {
    return static_cast<int64_t>(
        std::chrono::system_clock::now().time_since_epoch() /
        std::chrono::seconds(1));
}

CborMap IpcHandler::handle(const std::string& method,
                            const CborMap& params,
                            const std::string& /*caller*/) {
    if (method == "inbox.get_pending")          return get_pending(params);
    if (method == "inbox.get")                  return get_message(params);
    if (method == "inbox.ack")                  return ack(params);
    if (method == "inbox.guard_info")           return guard_info(params);
    if (method == "inbox.update_dht_delegation")return update_dht_delegation(params);
    if (method == "inbox.update_contact_outboxes") return update_contact_outboxes(params);
    if (method == "inbox.update_sender_allowlist") return update_sender_allowlist(params);
    if (method == "inbox.add_sibling")          return add_sibling(params);
    if (method == "inbox.remove_sibling")       return remove_sibling(params);
    if (method == "inbox.set_retention_days")   return set_retention_days(params);
    if (method == "inbox.status")               return status(params);
    throw std::runtime_error("unknown method: " + method);
}

// ── inbox.get_pending ─────────────────────────────────────────────────────────

CborMap IpcHandler::get_pending(const CborMap& /*p*/) {
    auto msgs = store_.get_pending(true);
    CborArray arr;
    arr.reserve(msgs.size());
    for (auto& m : msgs)
        arr.push_back(CborValue::from_string(m.message_id));
    return {{"message_ids", CborValue::from_array(std::move(arr))}};
}

// ── inbox.get ─────────────────────────────────────────────────────────────────

CborMap IpcHandler::get_message(const CborMap& p) {
    std::string id = req_string(p, "message_id");
    auto msg = store_.get_message(id);
    if (!msg) throw std::runtime_error("message not found: " + id);
    return {{"message_id",    CborValue::from_string(msg->message_id)},
            {"sender_id",     CborValue::from_string(msg->sender_id)},
            {"delivery_frame",CborValue::from_bytes(msg->delivery_frame)},
            {"persistence",   CborValue::from_string(msg->persistence)}};
}

// ── inbox.ack ─────────────────────────────────────────────────────────────────

CborMap IpcHandler::ack(const CborMap& p) {
    std::string id = req_string(p, "message_id");
    auto msg = store_.get_message(id);
    if (!msg) throw std::runtime_error("message not found: " + id);

    if (msg->persistence == "pass_through") {
        store_.delete_message(id);
    } else {
        int64_t expires = now_s() + (int64_t)store_.get_retention_days() * 86400;
        store_.mark_delivered(id, expires);
    }
    return {{"message_id", CborValue::from_string(id)},
            {"ok",         CborValue::from_bool(true)}};
}

// ── inbox.guard_info ──────────────────────────────────────────────────────────

CborMap IpcHandler::guard_info(const CborMap& /*p*/) {
    return guard_info_cb_();
}

// ── inbox.update_dht_delegation ───────────────────────────────────────────────

CborMap IpcHandler::update_dht_delegation(const CborMap& p) {
    DhtCredentials creds;
    creds.key_c_pubkey    = req_bytes(p, "key_c_pubkey");
    creds.key_c_privkey   = req_bytes(p, "key_c_privkey");
    creds.auth_cert       = req_bytes(p, "auth_cert");
    creds.delegation_cert = req_bytes(p, "delegation_cert");
    store_.set_dht_credentials(creds);
    return {{"ok", CborValue::from_bool(true)}};
}

// ── inbox.update_contact_outboxes ─────────────────────────────────────────────

CborMap IpcHandler::update_contact_outboxes(const CborMap& p) {
    auto it = p.find("outboxes");
    if (it == p.end() || !it->second.is_array())
        throw std::runtime_error("outboxes must be an array");
    const auto& arr = it->second.as_array();
    std::vector<KnownOutbox> list;
    for (auto& v : arr) {
        if (!v.is_map()) continue;
        const auto& m = v.as_map();
        KnownOutbox o;
        auto ki = m.find("key_c_pubkey");
        auto ai = m.find("auth_cert");
        auto ei = m.find("expires_at");
        if (ki == m.end() || !ki->second.is_bytes()) continue;
        if (ai == m.end() || !ai->second.is_bytes()) continue;
        o.key_c_pubkey = ki->second.as_bytes();
        o.auth_cert    = ai->second.as_bytes();
        if (ei != m.end() && ei->second.is_uint())
            o.expires_at = static_cast<int64_t>(ei->second.as_uint());
        list.push_back(std::move(o));
    }
    store_.replace_known_outboxes(list);
    return {{"ok", CborValue::from_bool(true)}};
}

// ── inbox.update_sender_allowlist ─────────────────────────────────────────────

CborMap IpcHandler::update_sender_allowlist(const CborMap& p) {
    auto it = p.find("sender_ids");
    if (it == p.end() || !it->second.is_array())
        throw std::runtime_error("sender_ids must be an array");
    std::vector<std::string> ids;
    for (auto& v : it->second.as_array()) {
        if (v.is_string()) ids.push_back(v.as_string());
    }
    store_.replace_allowed_senders(ids);
    return {{"ok", CborValue::from_bool(true)}};
}

// ── inbox.add_sibling ─────────────────────────────────────────────────────────

CborMap IpcHandler::add_sibling(const CborMap& p) {
    SiblingInbox s;
    s.key_c_pubkey = req_bytes(p, "key_c_pubkey");
    s.auth_cert    = req_bytes(p, "auth_cert");
    // device_id = hex(SHA3-256(key_c_pubkey)) — computed by Inbox on add.
    {
        auto it = p.find("device_id");
        if (it != p.end() && it->second.is_string())
            s.device_id = it->second.as_string();
    }
    store_.upsert_sibling(s);
    return {{"ok", CborValue::from_bool(true)}};
}

// ── inbox.remove_sibling ──────────────────────────────────────────────────────

CborMap IpcHandler::remove_sibling(const CborMap& p) {
    std::string id = req_string(p, "device_id");
    store_.remove_sibling(id);
    return {{"ok", CborValue::from_bool(true)}};
}

// ── inbox.set_retention_days ─────────────────────────────────────────────────

CborMap IpcHandler::set_retention_days(const CborMap& p) {
    auto it = p.find("days");
    if (it == p.end() || !it->second.is_uint())
        throw std::runtime_error("days must be uint");
    int days = static_cast<int>(it->second.as_uint());
    if (days < 1 || days > 365) throw std::runtime_error("days out of range");
    store_.set_retention_days(days);
    return {{"ok", CborValue::from_bool(true)}};
}

// ── inbox.status ──────────────────────────────────────────────────────────────

CborMap IpcHandler::status(const CborMap& /*p*/) {
    auto pending = store_.get_pending(true);
    auto creds   = store_.get_dht_credentials();
    bool renewal_needed = false;
    if (creds) {
        // Parse expires_at from auth_cert — stub: always false until Client sets up creds.
        renewal_needed = false;
    }
    return {
        {"pending_count",   CborValue::from_uint(pending.size())},
        {"has_credentials", CborValue::from_bool(creds.has_value())},
        {"renewal_needed",  CborValue::from_bool(renewal_needed)},
    };
}

} // namespace sw::inbox
