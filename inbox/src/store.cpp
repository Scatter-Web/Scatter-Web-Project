#include "store.hpp"

namespace sw::inbox {

using namespace sw::store;

InboxStore::InboxStore(const std::string& path) : db_(path) {
    init_schema();
}

void InboxStore::init_schema() {
    db_.exec(R"(
        CREATE TABLE IF NOT EXISTS stored_messages (
            message_id           TEXT PRIMARY KEY,
            sender_id            TEXT NOT NULL,
            delivery_frame       BLOB NOT NULL,
            persistence          TEXT NOT NULL DEFAULT 'store',
            delivered_to_client  INTEGER NOT NULL DEFAULT 0,
            replicated           INTEGER NOT NULL DEFAULT 0,
            received_at_ms       INTEGER NOT NULL,
            expires_at           INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_sm_delivered ON stored_messages(delivered_to_client);
        CREATE TABLE IF NOT EXISTS sibling_inboxes (
            device_id    TEXT PRIMARY KEY,
            key_c_pubkey BLOB NOT NULL,
            auth_cert    BLOB NOT NULL,
            channel_id   TEXT NOT NULL DEFAULT '',
            last_seen_ms INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sibling_replication_status (
            message_id TEXT NOT NULL,
            device_id  TEXT NOT NULL,
            replicated INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (message_id, device_id)
        );
        CREATE TABLE IF NOT EXISTS dht_credentials (
            id               INTEGER PRIMARY KEY CHECK(id=1),
            key_c_pubkey     BLOB NOT NULL,
            key_c_privkey    BLOB NOT NULL,
            auth_cert        BLOB NOT NULL,
            delegation_cert  BLOB NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS known_outboxes (
            key_c_pubkey BLOB NOT NULL,
            auth_cert    BLOB NOT NULL,
            expires_at   INTEGER NOT NULL,
            PRIMARY KEY (key_c_pubkey)
        );
        CREATE TABLE IF NOT EXISTS allowed_senders (
            sender_id TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS cr_guard_rate_limit (
            hour_bucket INTEGER NOT NULL,
            frame_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (hour_bucket)
        );
        CREATE TABLE IF NOT EXISTS inbox_config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    )");
}

// ── stored_messages ───────────────────────────────────────────────────────────

bool InboxStore::insert_message(const StoredMessage& msg) {
    if (message_exists(msg.message_id)) return false;
    auto s = db_.prepare(
        "INSERT INTO stored_messages"
        "(message_id,sender_id,delivery_frame,persistence,"
        "delivered_to_client,replicated,received_at_ms,expires_at)"
        " VALUES(?,?,?,?,?,?,?,?)");
    s.bind_text(1, msg.message_id);
    s.bind_text(2, msg.sender_id);
    s.bind_blob(3, ByteSpan{msg.delivery_frame.data(), msg.delivery_frame.size()});
    s.bind_text(4, msg.persistence);
    s.bind_int (5, msg.delivered_to_client ? 1 : 0);
    s.bind_int (6, msg.replicated          ? 1 : 0);
    s.bind_int (7, msg.received_at_ms);
    s.bind_int (8, msg.expires_at);
    s.exec();
    return true;
}

bool InboxStore::message_exists(const std::string& id) const {
    auto s = db_.prepare("SELECT 1 FROM stored_messages WHERE message_id=?");
    s.bind_text(1, id);
    bool found = false;
    s.query_one([&](const Row&) { found = true; });
    return found;
}

std::optional<StoredMessage> InboxStore::get_message(const std::string& id) const {
    auto s = db_.prepare(
        "SELECT message_id,sender_id,delivery_frame,persistence,"
        "delivered_to_client,replicated,received_at_ms,expires_at"
        " FROM stored_messages WHERE message_id=?");
    s.bind_text(1, id);
    std::optional<StoredMessage> out;
    s.query_one([&](const Row& r) {
        StoredMessage m;
        m.message_id         = r.require_text(0);
        m.sender_id          = r.require_text(1);
        m.delivery_frame     = r.require_blob(2);
        m.persistence        = r.require_text(3);
        m.delivered_to_client= r.require_int(4) != 0;
        m.replicated         = r.require_int(5) != 0;
        m.received_at_ms     = r.require_int(6);
        m.expires_at         = r.require_int(7);
        out = m;
    });
    return out;
}

std::vector<StoredMessage> InboxStore::get_pending(bool undelivered_only) const {
    std::string sql =
        "SELECT message_id,sender_id,delivery_frame,persistence,"
        "delivered_to_client,replicated,received_at_ms,expires_at"
        " FROM stored_messages";
    if (undelivered_only) sql += " WHERE delivered_to_client=0";
    auto s = db_.prepare(sql);
    std::vector<StoredMessage> out;
    s.query([&](const Row& r) {
        StoredMessage m;
        m.message_id         = r.require_text(0);
        m.sender_id          = r.require_text(1);
        m.delivery_frame     = r.require_blob(2);
        m.persistence        = r.require_text(3);
        m.delivered_to_client= r.require_int(4) != 0;
        m.replicated         = r.require_int(5) != 0;
        m.received_at_ms     = r.require_int(6);
        m.expires_at         = r.require_int(7);
        out.push_back(std::move(m));
    });
    return out;
}

void InboxStore::mark_delivered(const std::string& id, int64_t expires_at) {
    auto s = db_.prepare(
        "UPDATE stored_messages SET delivered_to_client=1, expires_at=? WHERE message_id=?");
    s.bind_int (1, expires_at);
    s.bind_text(2, id);
    s.exec();
}

void InboxStore::delete_message(const std::string& id) {
    auto s = db_.prepare("DELETE FROM stored_messages WHERE message_id=?");
    s.bind_text(1, id);
    s.exec();
}

void InboxStore::delete_expired(int64_t now_s) {
    auto s = db_.prepare(
        "DELETE FROM stored_messages WHERE expires_at>0 AND expires_at<?");
    s.bind_int(1, now_s);
    s.exec();
}

// ── sibling_inboxes ───────────────────────────────────────────────────────────

void InboxStore::upsert_sibling(const SiblingInbox& sib) {
    auto st = db_.prepare(
        "INSERT OR REPLACE INTO sibling_inboxes"
        "(device_id,key_c_pubkey,auth_cert,channel_id,last_seen_ms)"
        " VALUES(?,?,?,?,?)");
    st.bind_text(1, sib.device_id);
    st.bind_blob(2, ByteSpan{sib.key_c_pubkey.data(), sib.key_c_pubkey.size()});
    st.bind_blob(3, ByteSpan{sib.auth_cert.data(),    sib.auth_cert.size()});
    st.bind_text(4, sib.channel_id);
    st.bind_int (5, sib.last_seen_ms);
    st.exec();
}

void InboxStore::remove_sibling(const std::string& device_id) {
    auto s = db_.prepare("DELETE FROM sibling_inboxes WHERE device_id=?");
    s.bind_text(1, device_id);
    s.exec();
}

std::vector<SiblingInbox> InboxStore::list_siblings() const {
    auto s = db_.prepare(
        "SELECT device_id,key_c_pubkey,auth_cert,channel_id,last_seen_ms"
        " FROM sibling_inboxes");
    std::vector<SiblingInbox> out;
    s.query([&](const Row& r) {
        SiblingInbox si;
        si.device_id    = r.require_text(0);
        si.key_c_pubkey = r.require_blob(1);
        si.auth_cert    = r.require_blob(2);
        si.channel_id   = r.require_text(3);
        si.last_seen_ms = r.require_int(4);
        out.push_back(std::move(si));
    });
    return out;
}

void InboxStore::set_sibling_channel(const std::string& device_id,
                                      const std::string& channel_id) {
    auto s = db_.prepare(
        "UPDATE sibling_inboxes SET channel_id=? WHERE device_id=?");
    s.bind_text(1, channel_id);
    s.bind_text(2, device_id);
    s.exec();
}

void InboxStore::set_sibling_replicated(const std::string& message_id,
                                         const std::string& device_id) {
    auto s = db_.prepare(
        "INSERT OR REPLACE INTO sibling_replication_status"
        "(message_id,device_id,replicated) VALUES(?,?,1)");
    s.bind_text(1, message_id);
    s.bind_text(2, device_id);
    s.exec();
}

// ── dht_credentials ───────────────────────────────────────────────────────────

std::optional<DhtCredentials> InboxStore::get_dht_credentials() const {
    auto s = db_.prepare(
        "SELECT key_c_pubkey,key_c_privkey,auth_cert,delegation_cert"
        " FROM dht_credentials WHERE id=1");
    std::optional<DhtCredentials> out;
    s.query_one([&](const Row& r) {
        DhtCredentials c;
        c.key_c_pubkey    = r.require_blob(0);
        c.key_c_privkey   = r.require_blob(1);
        c.auth_cert       = r.require_blob(2);
        c.delegation_cert = r.require_blob(3);
        out = c;
    });
    return out;
}

void InboxStore::set_dht_credentials(const DhtCredentials& creds) {
    auto s = db_.prepare(
        "INSERT OR REPLACE INTO dht_credentials"
        "(id,key_c_pubkey,key_c_privkey,auth_cert,delegation_cert)"
        " VALUES(1,?,?,?,?)");
    s.bind_blob(1, ByteSpan{creds.key_c_pubkey.data(),    creds.key_c_pubkey.size()});
    s.bind_blob(2, ByteSpan{creds.key_c_privkey.data(),   creds.key_c_privkey.size()});
    s.bind_blob(3, ByteSpan{creds.auth_cert.data(),       creds.auth_cert.size()});
    s.bind_blob(4, ByteSpan{creds.delegation_cert.data(), creds.delegation_cert.size()});
    s.exec();
}

// ── known_outboxes ────────────────────────────────────────────────────────────

void InboxStore::replace_known_outboxes(const std::vector<KnownOutbox>& list) {
    auto tx = db_.transaction();
    db_.exec("DELETE FROM known_outboxes");
    for (auto& o : list) {
        auto s = db_.prepare(
            "INSERT INTO known_outboxes(key_c_pubkey,auth_cert,expires_at) VALUES(?,?,?)");
        s.bind_blob(1, ByteSpan{o.key_c_pubkey.data(), o.key_c_pubkey.size()});
        s.bind_blob(2, ByteSpan{o.auth_cert.data(),    o.auth_cert.size()});
        s.bind_int (3, o.expires_at);
        s.exec();
    }
    tx.commit();
}

std::vector<KnownOutbox> InboxStore::list_known_outboxes() const {
    auto s = db_.prepare(
        "SELECT key_c_pubkey,auth_cert,expires_at FROM known_outboxes");
    std::vector<KnownOutbox> out;
    s.query([&](const Row& r) {
        KnownOutbox o;
        o.key_c_pubkey = r.require_blob(0);
        o.auth_cert    = r.require_blob(1);
        o.expires_at   = r.require_int(2);
        out.push_back(std::move(o));
    });
    return out;
}

// ── allowed_senders ───────────────────────────────────────────────────────────

void InboxStore::replace_allowed_senders(const std::vector<std::string>& ids) {
    auto tx = db_.transaction();
    db_.exec("DELETE FROM allowed_senders");
    for (auto& id : ids) {
        auto s = db_.prepare("INSERT INTO allowed_senders(sender_id) VALUES(?)");
        s.bind_text(1, id);
        s.exec();
    }
    tx.commit();
}

bool InboxStore::is_allowed_sender(const std::string& id) const {
    auto s = db_.prepare("SELECT 1 FROM allowed_senders WHERE sender_id=?");
    s.bind_text(1, id);
    bool found = false;
    s.query_one([&](const Row&) { found = true; });
    return found;
}

// ── cr_guard_rate_limit ───────────────────────────────────────────────────────

int InboxStore::cr_guard_count_this_hour(int64_t now_s) const {
    int64_t bucket = now_s / 3600;
    auto s = db_.prepare(
        "SELECT frame_count FROM cr_guard_rate_limit WHERE hour_bucket=?");
    s.bind_int(1, bucket);
    int count = 0;
    s.query_one([&](const Row& r) { count = static_cast<int>(r.require_int(0)); });
    return count;
}

void InboxStore::cr_guard_record(int64_t now_s) {
    int64_t bucket = now_s / 3600;
    // Prune old buckets first.
    auto del = db_.prepare("DELETE FROM cr_guard_rate_limit WHERE hour_bucket<?");
    del.bind_int(1, bucket);
    del.exec();

    auto s = db_.prepare(
        "INSERT INTO cr_guard_rate_limit(hour_bucket,frame_count) VALUES(?,1)"
        " ON CONFLICT(hour_bucket) DO UPDATE SET frame_count=frame_count+1");
    s.bind_int(1, bucket);
    s.exec();
}

// ── retention ─────────────────────────────────────────────────────────────────

void InboxStore::set_retention_days(int days) {
    retention_days_ = days;
    auto s = db_.prepare(
        "INSERT OR REPLACE INTO inbox_config(key,value) VALUES('retention_days',?)");
    s.bind_text(1, std::to_string(days));
    s.exec();
}

int InboxStore::get_retention_days() const {
    return retention_days_;
}

} // namespace sw::inbox
