#include "ipc_handler.hpp"
#include "frame_parser.hpp"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace sw::outbox {

using namespace sw::ipc;

static int64_t now_ms() {
    return static_cast<int64_t>(
        std::chrono::system_clock::now().time_since_epoch() /
        std::chrono::milliseconds(1));
}

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

CborMap IpcHandler::handle(const std::string& method,
                             const CborMap& params,
                             const std::string& /*caller*/) {
    if (method == "outbox.enqueue")           return enqueue(params);
    if (method == "outbox.enqueue_broadcast") return enqueue_broadcast(params);
    if (method == "outbox.status")            return status(params);
    if (method == "outbox.broadcast_status")  return broadcast_status(params);
    if (method == "outbox.cancel")            return cancel(params);
    if (method == "outbox.list_pending")      return list_pending(params);
    if (method == "outbox.stats")             return stats(params);
    if (method == "outbox.add_sibling")       return add_sibling(params);
    if (method == "outbox.remove_sibling")    return remove_sibling(params);
    if (method == "outbox.update_auth_cert")  return update_auth_cert(params);
    throw std::runtime_error("unknown method: " + method);
}

// ── outbox.enqueue ────────────────────────────────────────────────────────────

CborMap IpcHandler::enqueue(const CborMap& p) {
    Bytes frame = req_bytes(p, "delivery_frame");

    DeliveryFrameHeader hdr;
    if (!parse_delivery_frame(ByteSpan{frame.data(), frame.size()}, hdr))
        throw std::runtime_error("malformed delivery_frame");

    // Accept recipient_inboxes from the Client.
    std::vector<RecipientInbox> inboxes;
    auto ri_it = p.find("recipient_inboxes");
    if (ri_it != p.end() && ri_it->second.is_array()) {
        for (auto& v : ri_it->second.as_array()) {
            if (!v.is_map()) continue;
            const auto& m = v.as_map();
            RecipientInbox ri;
            ri.message_id = hdr.message_id;
            auto ki = m.find("key_c_pubkey");
            auto ai = m.find("auth_cert");
            if (ki == m.end() || !ki->second.is_bytes()) continue;
            if (ai == m.end() || !ai->second.is_bytes()) continue;
            ri.key_c_pubkey = ki->second.as_bytes();
            ri.auth_cert    = ai->second.as_bytes();
            inboxes.push_back(std::move(ri));
        }
    }

    int64_t t = now_ms();
    auto ttl_it = p.find("ttl_ms");
    int64_t ttl = (ttl_it != p.end() && ttl_it->second.is_uint())
                ? static_cast<int64_t>(ttl_it->second.as_uint())
                : int64_t(7) * 86400 * 1000;

    QueuedMessage msg;
    msg.message_id                     = hdr.message_id;
    msg.recipient_key_b_kem_pubkey_hex = hdr.recipient_key_b_kem_pubkey_hex;
    msg.delivery_frame                 = frame;
    msg.enqueued_at_ms                 = t;
    msg.expires_at_ms                  = t + ttl;
    msg.next_attempt_at                = t;  // attempt immediately

    if (!store_.insert_message(msg)) {
        // 2001: DUPLICATE_MESSAGE_ID
        throw std::runtime_error("DUPLICATE_MESSAGE_ID");
    }
    for (auto& ri : inboxes)
        store_.add_recipient_inbox(ri);

    enqueue_cb_(hdr.message_id);

    return {{"message_id", CborValue::from_string(hdr.message_id)},
            {"ok",         CborValue::from_bool(true)}};
}

// ── outbox.enqueue_broadcast ──────────────────────────────────────────────────

CborMap IpcHandler::enqueue_broadcast(const CborMap& p) {
    Bytes frame = req_bytes(p, "delivery_frame");
    DeliveryFrameHeader hdr;
    if (!parse_delivery_frame(ByteSpan{frame.data(), frame.size()}, hdr))
        throw std::runtime_error("malformed delivery_frame");

    auto ri_it = p.find("recipients");
    if (ri_it == p.end() || !ri_it->second.is_array())
        throw std::runtime_error("recipients must be an array");

    int64_t t   = now_ms();
    int64_t ttl = int64_t(7) * 86400 * 1000;

    // One queued_message row per recipient (same frame, different key_b).
    std::vector<std::string> enqueued_ids;
    for (auto& v : ri_it->second.as_array()) {
        if (!v.is_map()) continue;
        const auto& m = v.as_map();
        auto kb = m.find("recipient_key_b_kem_pubkey_hex");
        if (kb == m.end() || !kb->second.is_string()) continue;

        // Synthesise a per-recipient message_id: hash of base + key_b hex.
        std::string per_id = hdr.message_id + "_" + kb->second.as_string().substr(0, 8);

        QueuedMessage msg;
        msg.message_id                     = per_id;
        msg.recipient_key_b_kem_pubkey_hex = kb->second.as_string();
        msg.delivery_frame                 = frame;
        msg.enqueued_at_ms                 = t;
        msg.expires_at_ms                  = t + ttl;
        msg.next_attempt_at                = t;
        if (store_.insert_message(msg)) {
            auto ki = m.find("key_c_pubkey");
            auto ai = m.find("auth_cert");
            if (ki != m.end() && ai != m.end()
                    && ki->second.is_bytes() && ai->second.is_bytes()) {
                RecipientInbox ri;
                ri.message_id   = per_id;
                ri.key_c_pubkey = ki->second.as_bytes();
                ri.auth_cert    = ai->second.as_bytes();
                store_.add_recipient_inbox(ri);
            }
            enqueue_cb_(per_id);
            enqueued_ids.push_back(per_id);
        }
    }
    CborArray arr;
    for (auto& id : enqueued_ids) arr.push_back(CborValue::from_string(id));
    return {{"enqueued_ids", CborValue::from_array(std::move(arr))},
            {"ok",           CborValue::from_bool(true)}};
}

// ── outbox.status ─────────────────────────────────────────────────────────────

CborMap IpcHandler::status(const CborMap& p) {
    std::string id = req_string(p, "message_id");
    auto msg = store_.get_message(id);
    if (!msg) throw std::runtime_error("MESSAGE_NOT_FOUND");
    std::string st;
    switch (msg->status) {
        case MsgStatus::PENDING:   st = "pending";   break;
        case MsgStatus::DELIVERED: st = "delivered"; break;
        case MsgStatus::EXPIRED:   st = "expired";   break;
        case MsgStatus::CANCELLED: st = "cancelled"; break;
    }
    return {{"message_id",    CborValue::from_string(id)},
            {"status",        CborValue::from_string(st)},
            {"attempt_count", CborValue::from_uint(msg->attempt_count)}};
}

// ── outbox.broadcast_status ───────────────────────────────────────────────────

CborMap IpcHandler::broadcast_status(const CborMap& p) {
    std::string base_id = req_string(p, "message_id");
    // Collect all messages that share the base_id prefix.
    auto all = store_.list_pending();
    size_t total = 0, delivered = 0;
    for (auto& m : all) {
        if (m.message_id.rfind(base_id, 0) == 0) {
            ++total;
            if (m.status == MsgStatus::DELIVERED) ++delivered;
        }
    }
    return {{"message_id", CborValue::from_string(base_id)},
            {"total",      CborValue::from_uint(total)},
            {"delivered",  CborValue::from_uint(delivered)}};
}

// ── outbox.cancel ─────────────────────────────────────────────────────────────

CborMap IpcHandler::cancel(const CborMap& p) {
    std::string id = req_string(p, "message_id");
    if (!store_.message_exists(id)) throw std::runtime_error("MESSAGE_NOT_FOUND");
    store_.set_status(id, MsgStatus::CANCELLED);
    return {{"message_id", CborValue::from_string(id)},
            {"ok",         CborValue::from_bool(true)}};
}

// ── outbox.list_pending ───────────────────────────────────────────────────────

CborMap IpcHandler::list_pending(const CborMap& /*p*/) {
    auto msgs = store_.list_pending();
    CborArray arr;
    arr.reserve(msgs.size());
    for (auto& m : msgs) {
        CborMap entry{
            {"message_id",    CborValue::from_string(m.message_id)},
            {"attempt_count", CborValue::from_uint(m.attempt_count)},
            {"expires_at_ms", CborValue::from_uint(static_cast<uint64_t>(m.expires_at_ms))},
        };
        arr.push_back(CborValue::from_map(std::move(entry)));
    }
    return {{"messages", CborValue::from_array(std::move(arr))}};
}

// ── outbox.stats ──────────────────────────────────────────────────────────────

CborMap IpcHandler::stats(const CborMap& /*p*/) {
    auto pending = store_.list_pending();
    return {{"pending_count", CborValue::from_uint(pending.size())}};
}

// ── outbox.add_sibling ────────────────────────────────────────────────────────

CborMap IpcHandler::add_sibling(const CborMap& p) {
    SiblingOutbox s;
    s.key_c_pubkey = req_bytes(p, "key_c_pubkey");
    s.auth_cert    = req_bytes(p, "auth_cert");
    {
        auto it = p.find("device_id");
        if (it != p.end() && it->second.is_string())
            s.device_id = it->second.as_string();
    }
    store_.upsert_sibling(s);
    return {{"ok", CborValue::from_bool(true)}};
}

// ── outbox.remove_sibling ────────────────────────────────────────────────────

CborMap IpcHandler::remove_sibling(const CborMap& p) {
    store_.remove_sibling(req_string(p, "device_id"));
    return {{"ok", CborValue::from_bool(true)}};
}

// ── outbox.update_auth_cert ───────────────────────────────────────────────────

CborMap IpcHandler::update_auth_cert(const CborMap& p) {
    Bytes pub  = req_bytes(p, "key_c_pubkey");
    Bytes priv = req_bytes(p, "key_c_privkey");
    Bytes cert = req_bytes(p, "auth_cert");
    store_.set_auth_cert(std::move(pub), std::move(priv), std::move(cert));
    return {{"ok", CborValue::from_bool(true)}};
}

} // namespace sw::outbox
