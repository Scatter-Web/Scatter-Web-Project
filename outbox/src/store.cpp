#include "store.hpp"

namespace sw::outbox {

using namespace sw::store;

OutboxStore::OutboxStore(const std::string& path) : db_(path) {
    init_schema();
}

void OutboxStore::init_schema() {
    db_.exec(R"(
        CREATE TABLE IF NOT EXISTS queued_messages (
            message_id                     TEXT PRIMARY KEY,
            recipient_key_b_kem_pubkey_hex TEXT NOT NULL,
            delivery_frame                 BLOB NOT NULL,
            priority                       INTEGER NOT NULL DEFAULT 0,
            enqueued_at_ms                INTEGER NOT NULL,
            expires_at_ms                 INTEGER NOT NULL,
            status                         INTEGER NOT NULL DEFAULT 0,
            attempt_count                  INTEGER NOT NULL DEFAULT 0,
            next_attempt_at               INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_qm_due ON queued_messages(next_attempt_at, status);
        CREATE TABLE IF NOT EXISTS recipient_inboxes (
            message_id   TEXT NOT NULL,
            key_c_pubkey BLOB NOT NULL,
            auth_cert    BLOB NOT NULL,
            PRIMARY KEY (message_id, key_c_pubkey)
        );
        CREATE TABLE IF NOT EXISTS broadcast_recipients (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS delivery_attempts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id      TEXT NOT NULL,
            attempted_at_ms INTEGER NOT NULL,
            outcome         TEXT NOT NULL,
            inbox_pubkey    BLOB
        );
        CREATE TABLE IF NOT EXISTS sibling_outboxes (
            device_id    TEXT PRIMARY KEY,
            key_c_pubkey BLOB NOT NULL,
            auth_cert    BLOB NOT NULL,
            channel_id   TEXT NOT NULL DEFAULT '',
            last_seen_ms INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS recipient_inbox_hints (
            recipient_key_b_kem_pubkey_hex TEXT NOT NULL,
            inbox_key_c_pubkey             BLOB NOT NULL,
            guard_node_id                  TEXT NOT NULL DEFAULT '',
            guard_endpoint                 TEXT NOT NULL DEFAULT '',
            session_token_expires          INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (recipient_key_b_kem_pubkey_hex, inbox_key_c_pubkey)
        );
        CREATE TABLE IF NOT EXISTS outbox_config (
            key   TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );
    )");
}

// ── queued_messages ───────────────────────────────────────────────────────────

bool OutboxStore::insert_message(const QueuedMessage& msg) {
    if (message_exists(msg.message_id)) return false;
    auto s = db_.prepare(
        "INSERT INTO queued_messages"
        "(message_id,recipient_key_b_kem_pubkey_hex,delivery_frame,priority,"
        "enqueued_at_ms,expires_at_ms,status,attempt_count,next_attempt_at)"
        " VALUES(?,?,?,?,?,?,?,?,?)");
    s.bind_text(1, msg.message_id);
    s.bind_text(2, msg.recipient_key_b_kem_pubkey_hex);
    s.bind_blob(3, ByteSpan{msg.delivery_frame.data(), msg.delivery_frame.size()});
    s.bind_int (4, msg.priority);
    s.bind_int (5, msg.enqueued_at_ms);
    s.bind_int (6, msg.expires_at_ms);
    s.bind_int (7, static_cast<int64_t>(msg.status));
    s.bind_int (8, msg.attempt_count);
    s.bind_int (9, msg.next_attempt_at);
    s.exec();
    return true;
}

bool OutboxStore::message_exists(const std::string& id) const {
    auto s = db_.prepare("SELECT 1 FROM queued_messages WHERE message_id=?");
    s.bind_text(1, id);
    bool found = false;
    s.query_one([&](const Row&) { found = true; });
    return found;
}

static QueuedMessage row_to_msg(const Row& r) {
    QueuedMessage m;
    m.message_id                     = r.require_text(0);
    m.recipient_key_b_kem_pubkey_hex = r.require_text(1);
    m.delivery_frame                 = r.require_blob(2);
    m.priority                       = static_cast<int32_t>(r.require_int(3));
    m.enqueued_at_ms                 = r.require_int(4);
    m.expires_at_ms                  = r.require_int(5);
    m.status                         = static_cast<MsgStatus>(r.require_int(6));
    m.attempt_count                  = static_cast<int32_t>(r.require_int(7));
    m.next_attempt_at                = r.require_int(8);
    return m;
}

std::optional<QueuedMessage> OutboxStore::get_message(const std::string& id) const {
    auto s = db_.prepare(
        "SELECT message_id,recipient_key_b_kem_pubkey_hex,delivery_frame,priority,"
        "enqueued_at_ms,expires_at_ms,status,attempt_count,next_attempt_at"
        " FROM queued_messages WHERE message_id=?");
    s.bind_text(1, id);
    std::optional<QueuedMessage> out;
    s.query_one([&](const Row& r) { out = row_to_msg(r); });
    return out;
}

std::vector<QueuedMessage> OutboxStore::list_pending() const {
    auto s = db_.prepare(
        "SELECT message_id,recipient_key_b_kem_pubkey_hex,delivery_frame,priority,"
        "enqueued_at_ms,expires_at_ms,status,attempt_count,next_attempt_at"
        " FROM queued_messages WHERE status=0");
    std::vector<QueuedMessage> out;
    s.query([&](const Row& r) { out.push_back(row_to_msg(r)); });
    return out;
}

std::vector<QueuedMessage> OutboxStore::list_due(int64_t now_ms_val) const {
    auto s = db_.prepare(
        "SELECT message_id,recipient_key_b_kem_pubkey_hex,delivery_frame,priority,"
        "enqueued_at_ms,expires_at_ms,status,attempt_count,next_attempt_at"
        " FROM queued_messages"
        " WHERE status=0 AND next_attempt_at>0 AND next_attempt_at<=?");
    s.bind_int(1, now_ms_val);
    std::vector<QueuedMessage> out;
    s.query([&](const Row& r) { out.push_back(row_to_msg(r)); });
    return out;
}

void OutboxStore::set_status(const std::string& id, MsgStatus st) {
    auto s = db_.prepare(
        "UPDATE queued_messages SET status=? WHERE message_id=?");
    s.bind_int (1, static_cast<int64_t>(st));
    s.bind_text(2, id);
    s.exec();
}

void OutboxStore::update_attempt(const std::string& id, int32_t count, int64_t next_at) {
    auto s = db_.prepare(
        "UPDATE queued_messages SET attempt_count=?, next_attempt_at=?"
        " WHERE message_id=?");
    s.bind_int (1, count);
    s.bind_int (2, next_at);
    s.bind_text(3, id);
    s.exec();
}

void OutboxStore::delete_message(const std::string& id) {
    auto s = db_.prepare("DELETE FROM queued_messages WHERE message_id=?");
    s.bind_text(1, id);
    s.exec();
}

void OutboxStore::expire_messages(int64_t now_ms_val) {
    auto s = db_.prepare(
        "UPDATE queued_messages SET status=2"
        " WHERE status=0 AND expires_at_ms>0 AND expires_at_ms<?");
    s.bind_int(1, now_ms_val);
    s.exec();
}

// ── recipient_inboxes ─────────────────────────────────────────────────────────

void OutboxStore::add_recipient_inbox(const RecipientInbox& r) {
    auto s = db_.prepare(
        "INSERT OR IGNORE INTO recipient_inboxes(message_id,key_c_pubkey,auth_cert)"
        " VALUES(?,?,?)");
    s.bind_text(1, r.message_id);
    s.bind_blob(2, ByteSpan{r.key_c_pubkey.data(), r.key_c_pubkey.size()});
    s.bind_blob(3, ByteSpan{r.auth_cert.data(),    r.auth_cert.size()});
    s.exec();
}

std::vector<RecipientInbox> OutboxStore::get_recipient_inboxes(
        const std::string& message_id) const {
    auto s = db_.prepare(
        "SELECT message_id,key_c_pubkey,auth_cert FROM recipient_inboxes"
        " WHERE message_id=?");
    s.bind_text(1, message_id);
    std::vector<RecipientInbox> out;
    s.query([&](const Row& r) {
        RecipientInbox ri;
        ri.message_id   = r.require_text(0);
        ri.key_c_pubkey = r.require_blob(1);
        ri.auth_cert    = r.require_blob(2);
        out.push_back(std::move(ri));
    });
    return out;
}

bool OutboxStore::is_valid_recipient_inbox(const std::string& message_id,
                                            const Bytes& key_c_pubkey) const {
    auto s = db_.prepare(
        "SELECT 1 FROM recipient_inboxes"
        " WHERE message_id=? AND key_c_pubkey=?");
    s.bind_text(1, message_id);
    s.bind_blob(2, ByteSpan{key_c_pubkey.data(), key_c_pubkey.size()});
    bool found = false;
    s.query_one([&](const Row&) { found = true; });
    return found;
}

// ── sibling_outboxes ──────────────────────────────────────────────────────────

void OutboxStore::upsert_sibling(const SiblingOutbox& sib) {
    auto s = db_.prepare(
        "INSERT OR REPLACE INTO sibling_outboxes"
        "(device_id,key_c_pubkey,auth_cert,channel_id,last_seen_ms)"
        " VALUES(?,?,?,?,?)");
    s.bind_text(1, sib.device_id);
    s.bind_blob(2, ByteSpan{sib.key_c_pubkey.data(), sib.key_c_pubkey.size()});
    s.bind_blob(3, ByteSpan{sib.auth_cert.data(),    sib.auth_cert.size()});
    s.bind_text(4, sib.channel_id);
    s.bind_int (5, sib.last_seen_ms);
    s.exec();
}

void OutboxStore::remove_sibling(const std::string& device_id) {
    auto s = db_.prepare("DELETE FROM sibling_outboxes WHERE device_id=?");
    s.bind_text(1, device_id);
    s.exec();
}

std::vector<SiblingOutbox> OutboxStore::list_siblings() const {
    auto s = db_.prepare(
        "SELECT device_id,key_c_pubkey,auth_cert,channel_id,last_seen_ms"
        " FROM sibling_outboxes");
    std::vector<SiblingOutbox> out;
    s.query([&](const Row& r) {
        SiblingOutbox so;
        so.device_id    = r.require_text(0);
        so.key_c_pubkey = r.require_blob(1);
        so.auth_cert    = r.require_blob(2);
        so.channel_id   = r.require_text(3);
        so.last_seen_ms = r.require_int(4);
        out.push_back(std::move(so));
    });
    return out;
}

void OutboxStore::set_sibling_channel(const std::string& device_id,
                                       const std::string& channel_id) {
    auto s = db_.prepare(
        "UPDATE sibling_outboxes SET channel_id=? WHERE device_id=?");
    s.bind_text(1, channel_id);
    s.bind_text(2, device_id);
    s.exec();
}

// ── inbox hints ───────────────────────────────────────────────────────────────

void OutboxStore::upsert_inbox_hint(const InboxHint& h) {
    auto s = db_.prepare(
        "INSERT OR REPLACE INTO recipient_inbox_hints"
        "(recipient_key_b_kem_pubkey_hex,inbox_key_c_pubkey,"
        "guard_node_id,guard_endpoint,session_token_expires)"
        " VALUES(?,?,?,?,?)");
    s.bind_text(1, h.recipient_key_b_kem_pubkey_hex);
    s.bind_blob(2, ByteSpan{h.inbox_key_c_pubkey.data(), h.inbox_key_c_pubkey.size()});
    s.bind_text(3, h.guard_node_id);
    s.bind_text(4, h.guard_endpoint);
    s.bind_int (5, h.session_token_expires);
    s.exec();
}

std::vector<InboxHint> OutboxStore::get_hints(const std::string& key_b_hex) const {
    auto s = db_.prepare(
        "SELECT recipient_key_b_kem_pubkey_hex,inbox_key_c_pubkey,"
        "guard_node_id,guard_endpoint,session_token_expires"
        " FROM recipient_inbox_hints WHERE recipient_key_b_kem_pubkey_hex=?");
    s.bind_text(1, key_b_hex);
    std::vector<InboxHint> out;
    s.query([&](const Row& r) {
        InboxHint h;
        h.recipient_key_b_kem_pubkey_hex = r.require_text(0);
        h.inbox_key_c_pubkey             = r.require_blob(1);
        h.guard_node_id                  = r.require_text(2);
        h.guard_endpoint                 = r.require_text(3);
        h.session_token_expires          = r.require_int(4);
        out.push_back(std::move(h));
    });
    return out;
}

// ── auth creds ────────────────────────────────────────────────────────────────

void OutboxStore::set_auth_cert(Bytes pub, Bytes priv, Bytes cert) {
    auto s1 = db_.prepare(
        "INSERT OR REPLACE INTO outbox_config(key,value) VALUES('key_c_pubkey',?)");
    s1.bind_blob(1, ByteSpan{pub.data(), pub.size()});
    s1.exec();

    auto s2 = db_.prepare(
        "INSERT OR REPLACE INTO outbox_config(key,value) VALUES('key_c_privkey',?)");
    s2.bind_blob(1, ByteSpan{priv.data(), priv.size()});
    s2.exec();

    auto s3 = db_.prepare(
        "INSERT OR REPLACE INTO outbox_config(key,value) VALUES('auth_cert',?)");
    s3.bind_blob(1, ByteSpan{cert.data(), cert.size()});
    s3.exec();
}

std::optional<OutboxStore::AuthCreds> OutboxStore::get_auth_creds() const {
    AuthCreds c;
    auto fetch = [&](const char* key, Bytes& dest) {
        auto s = db_.prepare("SELECT value FROM outbox_config WHERE key=?");
        s.bind_text(1, key);
        s.query_one([&](const Row& r) { dest = r.require_blob(0); });
    };
    fetch("key_c_pubkey",  c.key_c_pubkey);
    fetch("key_c_privkey", c.key_c_privkey);
    fetch("auth_cert",     c.auth_cert);
    if (c.key_c_pubkey.empty() || c.auth_cert.empty()) return std::nullopt;
    return c;
}

} // namespace sw::outbox
