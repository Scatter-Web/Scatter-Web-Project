#include "ipc_handler.hpp"
#include <sw/crypto/kdf.hpp>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace sw::anonrouter {

using namespace sw::ipc;
using namespace sw::crypto;

// ── Param helpers ─────────────────────────────────────────────────────────────

static std::string get_string(const CborMap& p, const std::string& key) {
    auto it = p.find(key);
    if (it == p.end()) throw std::runtime_error("missing param: " + key);
    if (!it->second.is_string()) throw std::runtime_error("param not string: " + key);
    return it->second.as_string();
}

static Bytes get_bytes(const CborMap& p, const std::string& key) {
    auto it = p.find(key);
    if (it == p.end()) throw std::runtime_error("missing param: " + key);
    if (!it->second.is_bytes()) throw std::runtime_error("param not bytes: " + key);
    return it->second.as_bytes();
}

static uint64_t get_uint(const CborMap& p, const std::string& key, uint64_t def = 0) {
    auto it = p.find(key);
    if (it == p.end()) return def;
    if (it->second.is_uint()) return it->second.as_uint();
    return def;
}

// ── Main dispatch ─────────────────────────────────────────────────────────────

CborMap IpcHandler::handle(const std::string& method,
                            const CborMap& params,
                            const std::string& /*caller*/) {
    if (method == "channel.open")         return channel_open(params);
    if (method == "channel.accept")       return channel_accept(params);
    if (method == "channel.reject")       return channel_reject(params);
    if (method == "channel.upgrade")      return channel_upgrade(params);
    if (method == "channel.close")        return channel_close(params);
    if (method == "channel.list")         return channel_list(params);
    if (method == "frame.send")           return frame_send(params);
    if (method == "frame.send_batch")     return frame_send_batch(params);
    if (method == "dht.lookup")           return dht_lookup(params);
    if (method == "dht.publish")          return dht_publish(params);
    if (method == "tft.status")           return tft_status(params);
    throw std::runtime_error("unknown method: " + method);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

std::string IpcHandler::chan_id_hex(const MessageId& id) {
    std::ostringstream ss;
    for (uint8_t b : id) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}

MessageId IpcHandler::from_hex(const std::string& h) {
    if (h.size() != 32) throw std::runtime_error("channel_id hex must be 32 chars");
    MessageId id{};
    for (size_t i = 0; i < 16; ++i)
        id[i] = static_cast<uint8_t>(std::stoi(h.substr(i * 2, 2), nullptr, 16));
    return id;
}

MessageId IpcHandler::require_channel_id(const CborMap& p) {
    return from_hex(get_string(p, "channel_id"));
}

// ── channel.open ──────────────────────────────────────────────────────────────

CborMap IpcHandler::channel_open(const CborMap& p) {
    std::string remote_pubkey = get_string(p, "remote_pubkey");
    uint64_t    anon_raw      = get_uint(p, "anon_level", 2);
    std::string mode_str      = "message";
    {
        auto it = p.find("mode");
        if (it != p.end() && it->second.is_string())
            mode_str = it->second.as_string();
    }
    AnonLevel anon = static_cast<AnonLevel>(anon_raw > 2 ? 2 : static_cast<uint8_t>(anon_raw));
    ChannelMode mode = (mode_str == "stream")   ? ChannelMode::STREAM
                     : (mode_str == "datagram") ? ChannelMode::DATAGRAM
                                                : ChannelMode::MESSAGE;
    MessageId id = channels_.open(remote_pubkey, anon, mode);
    return {{"channel_id", CborValue::from_string(chan_id_hex(id))},
            {"ok",         CborValue::from_bool(true)}};
}

// ── channel.accept ────────────────────────────────────────────────────────────

CborMap IpcHandler::channel_accept(const CborMap& p) {
    MessageId id = from_hex(get_string(p, "channel_id"));
    bool ok = channels_.accept(id);
    return {{"channel_id", CborValue::from_string(chan_id_hex(id))},
            {"ok",         CborValue::from_bool(ok)}};
}

// ── channel.reject ────────────────────────────────────────────────────────────

CborMap IpcHandler::channel_reject(const CborMap& p) {
    MessageId id = from_hex(get_string(p, "channel_id"));
    channels_.reject(id);
    return {{"channel_id", CborValue::from_string(chan_id_hex(id))},
            {"ok",         CborValue::from_bool(true)}};
}

// ── channel.upgrade ───────────────────────────────────────────────────────────

CborMap IpcHandler::channel_upgrade(const CborMap& p) {
    MessageId  id       = from_hex(get_string(p, "channel_id"));
    std::string mode_s  = get_string(p, "mode");
    Bytes csk_bytes     = get_bytes(p, "csk");
    if (csk_bytes.size() != 32)
        throw std::runtime_error("csk must be 32 bytes");
    ChannelMode mode = (mode_s == "stream") ? ChannelMode::STREAM : ChannelMode::MESSAGE;
    crypto::AesKey csk{};
    std::copy(csk_bytes.begin(), csk_bytes.end(), csk.begin());
    bool ok = channels_.upgrade(id, mode, csk);
    return {{"channel_id", CborValue::from_string(chan_id_hex(id))},
            {"ok",         CborValue::from_bool(ok)}};
}

// ── channel.close ─────────────────────────────────────────────────────────────

CborMap IpcHandler::channel_close(const CborMap& p) {
    MessageId id = from_hex(get_string(p, "channel_id"));
    channels_.close(id);
    return {{"channel_id", CborValue::from_string(chan_id_hex(id))},
            {"closed",     CborValue::from_bool(true)}};
}

// ── channel.list ──────────────────────────────────────────────────────────────

CborMap IpcHandler::channel_list(const CborMap& /*p*/) {
    auto list = channels_.list();
    CborArray arr;
    arr.reserve(list.size());
    for (auto& ci : list) {
        std::string state_s;
        switch (ci.state) {
            case ChannelState::OPENING:   state_s = "opening";   break;
            case ChannelState::OPEN:      state_s = "open";      break;
            case ChannelState::UPGRADING: state_s = "upgrading"; break;
            case ChannelState::CLOSED:    state_s = "closed";    break;
        }
        std::string mode_s;
        switch (ci.mode) {
            case ChannelMode::DATAGRAM: mode_s = "datagram"; break;
            case ChannelMode::MESSAGE:  mode_s = "message";  break;
            case ChannelMode::STREAM:   mode_s = "stream";   break;
        }
        CborMap entry{
            {"channel_id",    CborValue::from_string(chan_id_hex(ci.channel_id))},
            {"remote_pubkey", CborValue::from_string(ci.remote_pubkey_hex)},
            {"state",         CborValue::from_string(state_s)},
            {"mode",          CborValue::from_string(mode_s)},
        };
        arr.push_back(CborValue::from_map(std::move(entry)));
    }
    return {{"channels", CborValue::from_array(std::move(arr))}};
}

// ── frame.send ────────────────────────────────────────────────────────────────

CborMap IpcHandler::frame_send(const CborMap& p) {
    MessageId id  = from_hex(get_string(p, "channel_id"));
    Bytes payload = get_bytes(p, "payload");
    bool ok = channels_.send(id, ByteSpan{payload.data(), payload.size()});
    return {{"channel_id", CborValue::from_string(chan_id_hex(id))},
            {"sent",       CborValue::from_bool(ok)}};
}

// ── frame.send_batch ──────────────────────────────────────────────────────────

CborMap IpcHandler::frame_send_batch(const CborMap& p) {
    MessageId id = from_hex(get_string(p, "channel_id"));
    auto it = p.find("frames");
    if (it == p.end() || !it->second.is_array())
        throw std::runtime_error("frames param must be an array");
    const auto& arr = it->second.as_array();
    uint32_t sent = 0;
    for (auto& v : arr) {
        if (!v.is_bytes()) continue;
        const auto& pl = v.as_bytes();
        if (channels_.send(id, ByteSpan{pl.data(), pl.size()})) ++sent;
    }
    return {{"channel_id",  CborValue::from_string(chan_id_hex(id))},
            {"sent_count",  CborValue::from_uint(sent)}};
}

// ── dht.lookup ────────────────────────────────────────────────────────────────

CborMap IpcHandler::dht_lookup(const CborMap& p) {
    Bytes key_bytes = get_bytes(p, "dht_key");
    if (key_bytes.size() != 32)
        throw std::runtime_error("dht_key must be 32 bytes");
    Key32 k{};
    std::copy(key_bytes.begin(), key_bytes.end(), k.begin());
    auto val = dht_.lookup_sync(k);
    if (!val) return {{"found", CborValue::from_bool(false)}};
    return {{"found", CborValue::from_bool(true)},
            {"value", CborValue::from_bytes(*val)}};
}

// ── dht.publish ───────────────────────────────────────────────────────────────

CborMap IpcHandler::dht_publish(const CborMap& p) {
    Bytes key_bytes = get_bytes(p, "dht_key");
    Bytes value     = get_bytes(p, "value");
    if (key_bytes.size() != 32)
        throw std::runtime_error("dht_key must be 32 bytes");
    Key32 k{};
    std::copy(key_bytes.begin(), key_bytes.end(), k.begin());
    dht_.publish(k, std::move(value));
    std::ostringstream ss;
    for (uint8_t b : k) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return {{"dht_key", CborValue::from_string(ss.str())}};
}

// ── tft.status ────────────────────────────────────────────────────────────────

CborMap IpcHandler::tft_status(const CborMap& /*p*/) {
    auto s = tft_.state();
    CborArray arr;
    arr.reserve(s.top_peers.size());
    for (auto& [pid, cred] : s.top_peers) {
        CborMap entry{
            {"peer_id", CborValue::from_string(pid)},
            {"credits", CborValue::from_int(cred)},
        };
        arr.push_back(CborValue::from_map(std::move(entry)));
    }
    return {
        {"unchoked_peer_count", CborValue::from_uint(s.unchoked_count)},
        {"opt_unchoked_peer",   CborValue::from_string(s.opt_unchoked_peer)},
        {"round_number",        CborValue::from_uint(static_cast<uint64_t>(s.round_number))},
        {"top_peers",           CborValue::from_array(std::move(arr))},
    };
}

} // namespace sw::anonrouter
