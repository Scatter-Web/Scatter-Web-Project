#include "ipc_handler.hpp"
#include "client.hpp"
#include <sw/crypto/kdf.hpp>
#include <stdexcept>

namespace sw::client {

using namespace sw::ipc;
using namespace sw::crypto;

IpcHandler::IpcHandler(Client& client) : client_(client) {}

CborMap IpcHandler::handle(const std::string& method,
                             const CborMap& params,
                             const std::string& /*caller*/) {
    if (method == "session.unlock")           return session_unlock(params);
    if (method == "session.lock")             return session_lock(params);
    if (method == "session.is_unlocked")      return session_is_unlocked(params);
    if (method == "session.change_passphrase")return session_change_passphrase(params);

    if (method == "identity.get_profile")     return identity_get_profile(params);
    if (method == "identity.set_display_name")return identity_set_display_name(params);

    if (method == "contacts.list")            return contacts_list(params);
    if (method == "contacts.get")             return contacts_get(params);
    if (method == "contacts.send_request")    return contacts_send_request(params);
    if (method == "contacts.accept_request")  return contacts_accept_request(params);
    if (method == "contacts.decline_request") return contacts_decline_request(params);
    if (method == "contacts.block")           return contacts_block(params);

    if (method == "conversations.list")       return conversations_list(params);
    if (method == "conversations.get")        return conversations_get(params);

    if (method == "messages.get")             return messages_get(params);
    if (method == "messages.send")            return messages_send(params);
    if (method == "messages.edit")            return messages_edit(params);
    if (method == "messages.delete")          return messages_delete(params);
    if (method == "messages.react")           return messages_react(params);
    if (method == "messages.unreact")         return messages_unreact(params);
    if (method == "messages.mark_read")       return messages_mark_read(params);
    if (method == "messages.send_typing")     return messages_send_typing(params);

    if (method == "groups.create")            return groups_create(params);
    if (method == "groups.invite")            return groups_invite(params);
    if (method == "groups.kick")              return groups_kick(params);
    if (method == "groups.leave")             return groups_leave(params);

    if (method == "servers.create_channel")   return servers_create_channel(params);
    if (method == "servers.set_member_role")  return servers_set_member_role(params);

    if (method == "devices.list")             return devices_list(params);
    if (method == "devices.revoke")           return devices_revoke(params);
    if (method == "devices.get_inbox_status") return devices_get_inbox_status(params);
    if (method == "devices.get_outbox_status")return devices_get_outbox_status(params);

    if (method == "network.get_status")       return network_get_status(params);

    throw std::runtime_error("unknown method: " + method);
}

// ── session ───────────────────────────────────────────────────────────────────

CborMap IpcHandler::session_unlock(const CborMap& p) {
    auto it = p.find("passphrase");
    if (it == p.end() || !it->second.is_string())
        throw std::runtime_error("missing passphrase");
    client_.unlock(it->second.as_string());
    CborMap result;
    result["ok"]                       = CborValue::from_bool(true);
    result["display_name"]             = CborValue::from_string(client_.get_display_name());
    result["key_a_pubkey_fingerprint"] = CborValue::from_string(client_.my_sender_id_hex());
    return result;
}

CborMap IpcHandler::session_lock(const CborMap& /*p*/) {
    client_.lock();
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

CborMap IpcHandler::session_is_unlocked(const CborMap& /*p*/) {
    CborMap result;
    result["unlocked"] = CborValue::from_bool(client_.is_unlocked());
    return result;
}

CborMap IpcHandler::session_change_passphrase(const CborMap& p) {
    auto cur = p.find("current_passphrase");
    auto nw  = p.find("new_passphrase");
    if (cur == p.end() || !cur->second.is_string() ||
        nw  == p.end() || !nw->second.is_string())
        throw std::runtime_error("missing passphrase fields");
    client_.change_passphrase(cur->second.as_string(), nw->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

// ── identity ──────────────────────────────────────────────────────────────────

CborMap IpcHandler::identity_get_profile(const CborMap& /*p*/) {
    CborMap result;
    result["display_name"]     = CborValue::from_string(client_.get_display_name());
    result["contact_card_uri"] = CborValue::from_string(client_.get_contact_card_uri());
    result["key_a_fingerprint"]= CborValue::from_string(client_.my_sender_id_hex());
    return result;
}

CborMap IpcHandler::identity_set_display_name(const CborMap& p) {
    auto it = p.find("display_name");
    if (it == p.end() || !it->second.is_string())
        throw std::runtime_error("missing display_name");
    client_.set_display_name(it->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

// ── contacts ──────────────────────────────────────────────────────────────────

CborMap IpcHandler::contacts_list(const CborMap& /*p*/) {
    auto contacts = client_.list_contacts();
    CborArray arr;
    for (const auto& c : contacts) {
        CborMap m;
        m["id"]           = CborValue::from_string(c.id);
        m["display_name"] = CborValue::from_string(c.display_name);
        m["status"]       = CborValue::from_string(c.status);
        arr.push_back(CborValue::from_map(std::move(m)));
    }
    CborMap result;
    result["contacts"] = CborValue::from_array(std::move(arr));
    return result;
}

CborMap IpcHandler::contacts_get(const CborMap& p) {
    auto it = p.find("contact_id");
    if (it == p.end() || !it->second.is_string())
        throw std::runtime_error("missing contact_id");
    auto c = client_.get_contact(it->second.as_string());
    if (!c) throw std::runtime_error("CONTACT_NOT_FOUND");
    CborMap result;
    result["id"]           = CborValue::from_string(c->id);
    result["display_name"] = CborValue::from_string(c->display_name);
    result["status"]       = CborValue::from_string(c->status);
    result["added_at"]     = CborValue::from_uint(static_cast<uint64_t>(c->added_at));
    return result;
}

CborMap IpcHandler::contacts_send_request(const CborMap& p) {
    auto it = p.find("contact_card_uri");
    if (it == p.end() || !it->second.is_string())
        throw std::runtime_error("missing contact_card_uri");
    client_.send_contact_request(it->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

CborMap IpcHandler::contacts_accept_request(const CborMap& p) {
    auto it = p.find("contact_id");
    if (it == p.end() || !it->second.is_string())
        throw std::runtime_error("missing contact_id");
    client_.accept_contact_request(it->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

CborMap IpcHandler::contacts_decline_request(const CborMap& p) {
    auto it = p.find("contact_id");
    if (it == p.end() || !it->second.is_string())
        throw std::runtime_error("missing contact_id");
    client_.decline_contact_request(it->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

CborMap IpcHandler::contacts_block(const CborMap& p) {
    auto it = p.find("contact_id");
    if (it == p.end() || !it->second.is_string())
        throw std::runtime_error("missing contact_id");
    client_.block_contact(it->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

// ── conversations ─────────────────────────────────────────────────────────────

CborMap IpcHandler::conversations_list(const CborMap& /*p*/) {
    auto convs = client_.list_conversations();
    CborArray arr;
    for (const auto& c : convs) {
        CborMap m;
        m["id"]           = CborValue::from_string(c.id);
        m["type"]         = CborValue::from_string(c.type);
        m["display_name"] = CborValue::from_string(c.display_name);
        m["unread_count"] = CborValue::from_uint(0);

        // Include last message preview.
        auto msgs = client_.get_messages(c.id, 0, 1);
        if (!msgs.empty()) {
            CborMap lm;
            lm["text_preview"] = CborValue::from_string(msgs.back().text);
            lm["sent_at"]      = CborValue::from_uint(static_cast<uint64_t>(msgs.back().sent_at));
            m["last_message"]  = CborValue::from_map(std::move(lm));
        }

        arr.push_back(CborValue::from_map(std::move(m)));
    }
    CborMap result;
    result["conversations"] = CborValue::from_array(std::move(arr));
    return result;
}

CborMap IpcHandler::conversations_get(const CborMap& p) {
    auto it = p.find("conversation_id");
    if (it == p.end() || !it->second.is_string())
        throw std::runtime_error("missing conversation_id");
    auto c = client_.get_conversation(it->second.as_string());
    if (!c) throw std::runtime_error("UNKNOWN_CONVERSATION");
    CborMap result;
    result["id"]           = CborValue::from_string(c->id);
    result["type"]         = CborValue::from_string(c->type);
    result["display_name"] = CborValue::from_string(c->display_name);
    result["created_at"]   = CborValue::from_uint(static_cast<uint64_t>(c->created_at));
    return result;
}

// ── messages ──────────────────────────────────────────────────────────────────

CborMap IpcHandler::messages_get(const CborMap& p) {
    auto cit = p.find("conversation_id");
    if (cit == p.end() || !cit->second.is_string())
        throw std::runtime_error("missing conversation_id");
    int64_t before_seq = 0;
    if (auto bit = p.find("before_id"); bit != p.end() && bit->second.is_uint())
        before_seq = static_cast<int64_t>(bit->second.as_uint());
    int limit = 50;
    if (auto lit = p.find("limit"); lit != p.end() && lit->second.is_uint())
        limit = static_cast<int>(lit->second.as_uint());
    if (limit > 100) limit = 100;

    auto msgs = client_.get_messages(cit->second.as_string(), before_seq, limit);
    CborArray arr;
    for (const auto& m : msgs) {
        CborMap mm;
        mm["id"]              = CborValue::from_string(m.id);
        mm["conversation_id"] = CborValue::from_string(m.conversation_id);
        mm["seq"]             = CborValue::from_uint(static_cast<uint64_t>(m.seq));
        mm["content_type"]    = CborValue::from_string(m.content_type);
        mm["text"]            = CborValue::from_string(m.text);
        {
            static constexpr char HEX[] = "0123456789abcdef";
            std::string sid_hex;
            sid_hex.reserve(m.sender_id.size() * 2);
            for (uint8_t b : m.sender_id) {
                sid_hex += HEX[b >> 4];
                sid_hex += HEX[b & 0xf];
            }
            mm["sender_id"] = CborValue::from_string(sid_hex);
        }
        mm["sent_at"]         = CborValue::from_uint(static_cast<uint64_t>(m.sent_at));
        mm["status"]          = CborValue::from_string(m.status);
        arr.push_back(CborValue::from_map(std::move(mm)));
    }
    CborMap result;
    result["messages"] = CborValue::from_array(std::move(arr));
    return result;
}

CborMap IpcHandler::messages_send(const CborMap& p) {
    auto cit = p.find("conversation_id");
    auto tit = p.find("text");
    if (cit == p.end() || !cit->second.is_string())
        throw std::runtime_error("missing conversation_id");
    std::string text;
    if (tit != p.end() && tit->second.is_string())
        text = tit->second.as_string();
    std::string reply_to;
    if (auto rit = p.find("reply_to_id");
        rit != p.end() && rit->second.is_string())
        reply_to = rit->second.as_string();

    std::string msg_id = client_.send_message(
        cit->second.as_string(), text, reply_to);
    CborMap result;
    result["message_id"] = CborValue::from_string(msg_id);
    result["ok"]         = CborValue::from_bool(true);
    return result;
}

CborMap IpcHandler::messages_edit(const CborMap& p) {
    auto mit = p.find("message_id");
    auto tit = p.find("new_text");
    if (mit == p.end() || !mit->second.is_string() ||
        tit == p.end() || !tit->second.is_string())
        throw std::runtime_error("missing fields");
    client_.send_edit(mit->second.as_string(), tit->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

CborMap IpcHandler::messages_delete(const CborMap& p) {
    auto it = p.find("message_id");
    if (it == p.end() || !it->second.is_string())
        throw std::runtime_error("missing message_id");
    client_.send_delete(it->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

CborMap IpcHandler::messages_react(const CborMap& p) {
    auto mit = p.find("message_id");
    auto eit = p.find("emoji");
    if (mit == p.end() || !mit->second.is_string() ||
        eit == p.end() || !eit->second.is_string())
        throw std::runtime_error("missing fields");
    client_.send_reaction(mit->second.as_string(), eit->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

CborMap IpcHandler::messages_unreact(const CborMap& p) {
    auto mit = p.find("message_id");
    auto eit = p.find("emoji");
    if (mit == p.end() || !mit->second.is_string() ||
        eit == p.end() || !eit->second.is_string())
        throw std::runtime_error("missing fields");
    client_.send_unreact(mit->second.as_string(), eit->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

CborMap IpcHandler::messages_mark_read(const CborMap& p) {
    auto cit = p.find("conversation_id");
    auto mit = p.find("up_to_message_id");
    if (cit == p.end() || !cit->second.is_string() ||
        mit == p.end() || !mit->second.is_string())
        throw std::runtime_error("missing fields");
    client_.mark_read(cit->second.as_string(), mit->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

CborMap IpcHandler::messages_send_typing(const CborMap& p) {
    auto cit = p.find("conversation_id");
    auto ait = p.find("action");
    if (cit == p.end() || !cit->second.is_string() ||
        ait == p.end() || !ait->second.is_string())
        throw std::runtime_error("missing fields");
    client_.send_typing(cit->second.as_string(), ait->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

// ── groups ────────────────────────────────────────────────────────────────────

CborMap IpcHandler::groups_create(const CborMap& p) {
    auto nit = p.find("name");
    auto tit = p.find("type");
    if (nit == p.end() || !nit->second.is_string() ||
        tit == p.end() || !tit->second.is_string())
        throw std::runtime_error("missing fields");
    std::string gid = client_.create_group(nit->second.as_string(),
                                            tit->second.as_string());
    CborMap result;
    result["group_id"]        = CborValue::from_string(gid);
    result["conversation_id"] = CborValue::from_string(gid);
    return result;
}

CborMap IpcHandler::groups_invite(const CborMap& p) {
    auto git = p.find("group_id");
    auto cit = p.find("contact_id");
    if (git == p.end() || !git->second.is_string() ||
        cit == p.end() || !cit->second.is_string())
        throw std::runtime_error("missing fields");
    client_.invite_to_group(git->second.as_string(), cit->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

CborMap IpcHandler::groups_kick(const CborMap& p) {
    auto git = p.find("group_id");
    auto cit = p.find("contact_id");
    if (git == p.end() || !git->second.is_string() ||
        cit == p.end() || !cit->second.is_string())
        throw std::runtime_error("missing fields");
    client_.kick_from_group(git->second.as_string(), cit->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

CborMap IpcHandler::groups_leave(const CborMap& p) {
    auto it = p.find("group_id");
    if (it == p.end() || !it->second.is_string())
        throw std::runtime_error("missing group_id");
    client_.leave_group(it->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

// ── servers ───────────────────────────────────────────────────────────────────

CborMap IpcHandler::servers_create_channel(const CborMap& p) {
    auto sit = p.find("server_id");
    auto nit = p.find("name");
    auto tit = p.find("type");
    if (sit == p.end() || !sit->second.is_string() ||
        nit == p.end() || !nit->second.is_string() ||
        tit == p.end() || !tit->second.is_string())
        throw std::runtime_error("missing fields");
    std::string cid = client_.create_server_channel(
        sit->second.as_string(), nit->second.as_string(), tit->second.as_string());
    CborMap result;
    result["channel_id"]       = CborValue::from_string(cid);
    result["conversation_id"]  = CborValue::from_string(cid);
    return result;
}

CborMap IpcHandler::servers_set_member_role(const CborMap& p) {
    auto sit = p.find("server_id");
    auto cit = p.find("contact_id");
    auto rit = p.find("role");
    if (sit == p.end() || !sit->second.is_string() ||
        cit == p.end() || !cit->second.is_string() ||
        rit == p.end() || !rit->second.is_string())
        throw std::runtime_error("missing fields");
    client_.set_server_member_role(
        sit->second.as_string(), cit->second.as_string(), rit->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

// ── devices ───────────────────────────────────────────────────────────────────

CborMap IpcHandler::devices_list(const CborMap& /*p*/) {
    auto devices = client_.list_devices();
    CborArray arr;
    for (const auto& d : devices) {
        CborMap m;
        m["device_id"]  = CborValue::from_string(d.device_id);
        m["type"]       = CborValue::from_string(d.device_type);
        m["label"]      = CborValue::from_string(d.device_label);
        m["issued_at"]  = CborValue::from_uint(static_cast<uint64_t>(d.issued_at));
        m["expires_at"] = CborValue::from_uint(static_cast<uint64_t>(d.expires_at));
        m["revoked"]    = CborValue::from_bool(d.revoked);
        arr.push_back(CborValue::from_map(std::move(m)));
    }
    CborMap result;
    result["devices"] = CborValue::from_array(std::move(arr));
    return result;
}

CborMap IpcHandler::devices_revoke(const CborMap& p) {
    auto it = p.find("device_id");
    if (it == p.end() || !it->second.is_string())
        throw std::runtime_error("missing device_id");
    client_.revoke_device(it->second.as_string());
    CborMap result;
    result["ok"] = CborValue::from_bool(true);
    return result;
}

CborMap IpcHandler::devices_get_inbox_status(const CborMap& /*p*/) {
    return client_.get_inbox_status();
}

CborMap IpcHandler::devices_get_outbox_status(const CborMap& /*p*/) {
    return client_.get_outbox_status();
}

// ── network ───────────────────────────────────────────────────────────────────

CborMap IpcHandler::network_get_status(const CborMap& /*p*/) {
    return client_.get_network_status();
}

} // namespace sw::client
