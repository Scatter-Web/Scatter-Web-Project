#include "store.hpp"
#include <ctime>

namespace sw::client {

using namespace sw::store;

MessageStore::MessageStore(const std::string& path) : db_(path) {
    init_schema();
}

void MessageStore::init_schema() {
    db_.exec(R"(
        CREATE TABLE IF NOT EXISTS conversations (
            id            TEXT PRIMARY KEY,
            type          TEXT NOT NULL,
            display_name  TEXT NOT NULL DEFAULT '',
            contact_id    TEXT NOT NULL DEFAULT '',
            group_id      TEXT NOT NULL DEFAULT '',
            last_read_seq INTEGER NOT NULL DEFAULT 0,
            created_at    INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            id              TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            sender_id       BLOB NOT NULL,
            seq             INTEGER NOT NULL,
            content_type    TEXT NOT NULL,
            text            TEXT NOT NULL DEFAULT '',
            ciphertext      BLOB NOT NULL,
            sent_at         INTEGER NOT NULL,
            received_at     INTEGER NOT NULL DEFAULT 0,
            status          TEXT NOT NULL DEFAULT 'pending',
            reply_to_id     TEXT NOT NULL DEFAULT '',
            UNIQUE(conversation_id, seq)
        );
        CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conversation_id, seq);
        CREATE TABLE IF NOT EXISTS known_certs (
            fingerprint BLOB PRIMARY KEY,
            auth_cert   BLOB NOT NULL,
            owner_id    TEXT NOT NULL,
            cached_at   INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reactions (
            message_id TEXT NOT NULL,
            contact_id TEXT NOT NULL,
            emoji      TEXT NOT NULL,
            added_at   INTEGER NOT NULL,
            PRIMARY KEY (message_id, contact_id, emoji)
        );
        CREATE TABLE IF NOT EXISTS contacts (
            id                  TEXT PRIMARY KEY,
            display_name        TEXT NOT NULL,
            key_a_pubkey        BLOB NOT NULL,
            their_dm_key_b_kem  BLOB NOT NULL DEFAULT '',
            their_dm_key_b_sig  BLOB NOT NULL DEFAULT '',
            my_key_b_id         TEXT NOT NULL DEFAULT '',
            their_key_c_pubkeys BLOB NOT NULL DEFAULT '',
            added_at            INTEGER NOT NULL,
            status              TEXT NOT NULL DEFAULT 'pending'
        );
        CREATE TABLE IF NOT EXISTS groups (
            id         TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            type       TEXT NOT NULL,
            my_role    TEXT NOT NULL DEFAULT 'member',
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS group_members (
            group_id       TEXT NOT NULL,
            contact_id     TEXT NOT NULL,
            their_key_b_kem BLOB NOT NULL,
            their_key_b_sig BLOB NOT NULL,
            my_key_b_id    TEXT NOT NULL DEFAULT '',
            role           TEXT NOT NULL DEFAULT 'member',
            joined_at      INTEGER NOT NULL,
            PRIMARY KEY (group_id, contact_id)
        );
        CREATE TABLE IF NOT EXISTS server_channels (
            id         TEXT PRIMARY KEY,
            server_id  TEXT NOT NULL,
            name       TEXT NOT NULL,
            type       TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS server_roles (
            server_id   TEXT NOT NULL,
            contact_id  TEXT NOT NULL,
            role        TEXT NOT NULL,
            assigned_at INTEGER NOT NULL,
            PRIMARY KEY (server_id, contact_id)
        );
    )");
}

// ── conversations ─────────────────────────────────────────────────────────────

void MessageStore::upsert_conversation(const Conversation& c) {
    auto s = db_.prepare(
        "INSERT OR REPLACE INTO conversations"
        "(id,type,display_name,contact_id,group_id,last_read_seq,created_at)"
        " VALUES(?,?,?,?,?,?,?)");
    s.bind_text(1, c.id);
    s.bind_text(2, c.type);
    s.bind_text(3, c.display_name);
    s.bind_text(4, c.contact_id);
    s.bind_text(5, c.group_id);
    s.bind_int (6, c.last_read_seq);
    s.bind_int (7, c.created_at);
    s.exec();
}

std::optional<Conversation> MessageStore::get_conversation(
        const std::string& id) const {
    auto s = db_.prepare(
        "SELECT id,type,display_name,contact_id,group_id,last_read_seq,created_at"
        " FROM conversations WHERE id=?");
    s.bind_text(1, id);
    std::optional<Conversation> out;
    s.query_one([&](const Row& r) {
        Conversation c;
        c.id           = r.require_text(0);
        c.type         = r.require_text(1);
        c.display_name = r.require_text(2);
        c.contact_id   = r.require_text(3);
        c.group_id     = r.require_text(4);
        c.last_read_seq= r.require_int(5);
        c.created_at   = r.require_int(6);
        out = c;
    });
    return out;
}

std::vector<Conversation> MessageStore::list_conversations() const {
    auto s = db_.prepare(
        "SELECT id,type,display_name,contact_id,group_id,last_read_seq,created_at"
        " FROM conversations ORDER BY created_at DESC");
    std::vector<Conversation> out;
    s.query([&](const Row& r) {
        Conversation c;
        c.id           = r.require_text(0);
        c.type         = r.require_text(1);
        c.display_name = r.require_text(2);
        c.contact_id   = r.require_text(3);
        c.group_id     = r.require_text(4);
        c.last_read_seq= r.require_int(5);
        c.created_at   = r.require_int(6);
        out.push_back(std::move(c));
    });
    return out;
}

void MessageStore::update_last_read(const std::string& conv_id, int64_t seq) {
    auto s = db_.prepare(
        "UPDATE conversations SET last_read_seq=? WHERE id=?");
    s.bind_int (1, seq);
    s.bind_text(2, conv_id);
    s.exec();
}

// ── messages ──────────────────────────────────────────────────────────────────

bool MessageStore::insert_message(const StoredMessage& m) {
    auto check = db_.prepare("SELECT 1 FROM messages WHERE id=?");
    check.bind_text(1, m.id);
    bool exists = false;
    check.query_one([&](const Row&) { exists = true; });
    if (exists) return false;

    auto s = db_.prepare(
        "INSERT INTO messages"
        "(id,conversation_id,sender_id,seq,content_type,text,ciphertext,"
        "sent_at,received_at,status,reply_to_id)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)");
    s.bind_text(1, m.id);
    s.bind_text(2, m.conversation_id);
    s.bind_blob(3, ByteSpan{m.sender_id.data(), m.sender_id.size()});
    s.bind_int (4, m.seq);
    s.bind_text(5, m.content_type);
    s.bind_text(6, m.text);
    s.bind_blob(7, ByteSpan{m.ciphertext.data(), m.ciphertext.size()});
    s.bind_int (8, m.sent_at);
    s.bind_int (9, m.received_at);
    s.bind_text(10, m.status);
    s.bind_text(11, m.reply_to_id);
    s.exec();
    return true;
}

std::optional<StoredMessage> MessageStore::get_message(
        const std::string& id) const {
    auto s = db_.prepare(
        "SELECT id,conversation_id,sender_id,seq,content_type,text,ciphertext,"
        "sent_at,received_at,status,reply_to_id FROM messages WHERE id=?");
    s.bind_text(1, id);
    std::optional<StoredMessage> out;
    s.query_one([&](const Row& r) {
        StoredMessage m;
        m.id              = r.require_text(0);
        m.conversation_id = r.require_text(1);
        m.sender_id       = r.require_blob(2);
        m.seq             = r.require_int(3);
        m.content_type    = r.require_text(4);
        m.text            = r.require_text(5);
        m.ciphertext      = r.require_blob(6);
        m.sent_at         = r.require_int(7);
        m.received_at     = r.require_int(8);
        m.status          = r.require_text(9);
        m.reply_to_id     = r.require_text(10);
        out = m;
    });
    return out;
}

std::vector<StoredMessage> MessageStore::list_messages(
        const std::string& conv_id,
        int64_t before_seq, int limit) const {
    std::string sql =
        "SELECT id,conversation_id,sender_id,seq,content_type,text,ciphertext,"
        "sent_at,received_at,status,reply_to_id"
        " FROM messages WHERE conversation_id=?";
    if (before_seq > 0) sql += " AND seq<?";
    sql += " ORDER BY seq DESC LIMIT ?";

    auto s = db_.prepare(sql);
    s.bind_text(1, conv_id);
    int next_idx = 2;
    if (before_seq > 0) { s.bind_int(next_idx++, before_seq); }
    s.bind_int(next_idx, limit);

    std::vector<StoredMessage> out;
    s.query([&](const Row& r) {
        StoredMessage m;
        m.id              = r.require_text(0);
        m.conversation_id = r.require_text(1);
        m.sender_id       = r.require_blob(2);
        m.seq             = r.require_int(3);
        m.content_type    = r.require_text(4);
        m.text            = r.require_text(5);
        m.ciphertext      = r.require_blob(6);
        m.sent_at         = r.require_int(7);
        m.received_at     = r.require_int(8);
        m.status          = r.require_text(9);
        m.reply_to_id     = r.require_text(10);
        out.push_back(std::move(m));
    });
    return out;
}

void MessageStore::update_message_status(const std::string& id,
                                          const std::string& status) {
    auto s = db_.prepare("UPDATE messages SET status=? WHERE id=?");
    s.bind_text(1, status);
    s.bind_text(2, id);
    s.exec();
}

int64_t MessageStore::next_seq(const std::string& conv_id) const {
    auto s = db_.prepare(
        "SELECT COALESCE(MAX(seq),0)+1 FROM messages WHERE conversation_id=?");
    s.bind_text(1, conv_id);
    int64_t result = 1;
    s.query_one([&](const Row& r) { result = r.require_int(0); });
    return result;
}

// ── known_certs ───────────────────────────────────────────────────────────────

std::optional<KnownCert> MessageStore::get_cert(const Bytes& fingerprint) const {
    auto s = db_.prepare(
        "SELECT fingerprint,auth_cert,owner_id,cached_at FROM known_certs"
        " WHERE fingerprint=?");
    s.bind_blob(1, ByteSpan{fingerprint.data(), fingerprint.size()});
    std::optional<KnownCert> out;
    s.query_one([&](const Row& r) {
        KnownCert c;
        c.fingerprint = r.require_blob(0);
        c.auth_cert   = r.require_blob(1);
        c.owner_id    = r.require_text(2);
        c.cached_at   = r.require_int(3);
        out = c;
    });
    return out;
}

void MessageStore::insert_cert(const KnownCert& c) {
    auto s = db_.prepare(
        "INSERT OR IGNORE INTO known_certs(fingerprint,auth_cert,owner_id,cached_at)"
        " VALUES(?,?,?,?)");
    s.bind_blob(1, ByteSpan{c.fingerprint.data(), c.fingerprint.size()});
    s.bind_blob(2, ByteSpan{c.auth_cert.data(),   c.auth_cert.size()});
    s.bind_text(3, c.owner_id);
    s.bind_int (4, c.cached_at);
    s.exec();
}

// ── reactions ─────────────────────────────────────────────────────────────────

void MessageStore::upsert_reaction(const Reaction& r) {
    auto s = db_.prepare(
        "INSERT OR REPLACE INTO reactions(message_id,contact_id,emoji,added_at)"
        " VALUES(?,?,?,?)");
    s.bind_text(1, r.message_id);
    s.bind_text(2, r.contact_id);
    s.bind_text(3, r.emoji);
    s.bind_int (4, r.added_at);
    s.exec();
}

void MessageStore::delete_reaction(const std::string& msg_id,
                                    const std::string& contact_id,
                                    const std::string& emoji) {
    auto s = db_.prepare(
        "DELETE FROM reactions WHERE message_id=? AND contact_id=? AND emoji=?");
    s.bind_text(1, msg_id);
    s.bind_text(2, contact_id);
    s.bind_text(3, emoji);
    s.exec();
}

std::vector<Reaction> MessageStore::get_reactions(const std::string& msg_id) const {
    auto s = db_.prepare(
        "SELECT message_id,contact_id,emoji,added_at FROM reactions WHERE message_id=?");
    s.bind_text(1, msg_id);
    std::vector<Reaction> out;
    s.query([&](const Row& r) {
        Reaction rx;
        rx.message_id = r.require_text(0);
        rx.contact_id = r.require_text(1);
        rx.emoji      = r.require_text(2);
        rx.added_at   = r.require_int(3);
        out.push_back(std::move(rx));
    });
    return out;
}

// ── contacts ──────────────────────────────────────────────────────────────────

static Contact row_to_contact(const Row& r) {
    Contact c;
    c.id                 = r.require_text(0);
    c.display_name       = r.require_text(1);
    c.key_a_pubkey       = r.require_blob(2);
    c.their_dm_key_b_kem = r.require_blob(3);
    c.their_dm_key_b_sig = r.require_blob(4);
    c.my_key_b_id        = r.require_text(5);
    c.their_key_c_pubkeys= r.require_blob(6);
    c.added_at           = r.require_int(7);
    c.status             = r.require_text(8);
    return c;
}

bool MessageStore::insert_contact(const Contact& c) {
    auto check = db_.prepare("SELECT 1 FROM contacts WHERE id=?");
    check.bind_text(1, c.id);
    bool exists = false;
    check.query_one([&](const Row&) { exists = true; });
    if (exists) return false;

    auto s = db_.prepare(
        "INSERT INTO contacts"
        "(id,display_name,key_a_pubkey,their_dm_key_b_kem,their_dm_key_b_sig,"
        "my_key_b_id,their_key_c_pubkeys,added_at,status)"
        " VALUES(?,?,?,?,?,?,?,?,?)");
    s.bind_text(1, c.id);
    s.bind_text(2, c.display_name);
    s.bind_blob(3, ByteSpan{c.key_a_pubkey.data(), c.key_a_pubkey.size()});
    s.bind_blob(4, ByteSpan{c.their_dm_key_b_kem.data(), c.their_dm_key_b_kem.size()});
    s.bind_blob(5, ByteSpan{c.their_dm_key_b_sig.data(), c.their_dm_key_b_sig.size()});
    s.bind_text(6, c.my_key_b_id);
    s.bind_blob(7, ByteSpan{c.their_key_c_pubkeys.data(), c.their_key_c_pubkeys.size()});
    s.bind_int (8, c.added_at);
    s.bind_text(9, c.status);
    s.exec();
    return true;
}

std::optional<Contact> MessageStore::get_contact(const std::string& id) const {
    auto s = db_.prepare(
        "SELECT id,display_name,key_a_pubkey,their_dm_key_b_kem,their_dm_key_b_sig,"
        "my_key_b_id,their_key_c_pubkeys,added_at,status FROM contacts WHERE id=?");
    s.bind_text(1, id);
    std::optional<Contact> out;
    s.query_one([&](const Row& r) { out = row_to_contact(r); });
    return out;
}

std::vector<Contact> MessageStore::list_contacts() const {
    auto s = db_.prepare(
        "SELECT id,display_name,key_a_pubkey,their_dm_key_b_kem,their_dm_key_b_sig,"
        "my_key_b_id,their_key_c_pubkeys,added_at,status FROM contacts");
    std::vector<Contact> out;
    s.query([&](const Row& r) { out.push_back(row_to_contact(r)); });
    return out;
}

void MessageStore::update_contact(const Contact& c) {
    auto s = db_.prepare(
        "UPDATE contacts SET display_name=?,their_dm_key_b_kem=?,their_dm_key_b_sig=?,"
        "my_key_b_id=?,their_key_c_pubkeys=?,status=? WHERE id=?");
    s.bind_text(1, c.display_name);
    s.bind_blob(2, ByteSpan{c.their_dm_key_b_kem.data(), c.their_dm_key_b_kem.size()});
    s.bind_blob(3, ByteSpan{c.their_dm_key_b_sig.data(), c.their_dm_key_b_sig.size()});
    s.bind_text(4, c.my_key_b_id);
    s.bind_blob(5, ByteSpan{c.their_key_c_pubkeys.data(), c.their_key_c_pubkeys.size()});
    s.bind_text(6, c.status);
    s.bind_text(7, c.id);
    s.exec();
}

void MessageStore::set_contact_status(const std::string& id,
                                       const std::string& status) {
    auto s = db_.prepare("UPDATE contacts SET status=? WHERE id=?");
    s.bind_text(1, status);
    s.bind_text(2, id);
    s.exec();
}

// ── groups ────────────────────────────────────────────────────────────────────

void MessageStore::upsert_group(const Group& g) {
    auto s = db_.prepare(
        "INSERT OR REPLACE INTO groups(id,name,type,my_role,created_at)"
        " VALUES(?,?,?,?,?)");
    s.bind_text(1, g.id);
    s.bind_text(2, g.name);
    s.bind_text(3, g.type);
    s.bind_text(4, g.my_role);
    s.bind_int (5, g.created_at);
    s.exec();
}

std::optional<Group> MessageStore::get_group(const std::string& id) const {
    auto s = db_.prepare(
        "SELECT id,name,type,my_role,created_at FROM groups WHERE id=?");
    s.bind_text(1, id);
    std::optional<Group> out;
    s.query_one([&](const Row& r) {
        Group g;
        g.id         = r.require_text(0);
        g.name       = r.require_text(1);
        g.type       = r.require_text(2);
        g.my_role    = r.require_text(3);
        g.created_at = r.require_int(4);
        out = g;
    });
    return out;
}

std::vector<Group> MessageStore::list_groups() const {
    auto s = db_.prepare("SELECT id,name,type,my_role,created_at FROM groups");
    std::vector<Group> out;
    s.query([&](const Row& r) {
        Group g;
        g.id         = r.require_text(0);
        g.name       = r.require_text(1);
        g.type       = r.require_text(2);
        g.my_role    = r.require_text(3);
        g.created_at = r.require_int(4);
        out.push_back(std::move(g));
    });
    return out;
}

// ── group_members ─────────────────────────────────────────────────────────────

void MessageStore::upsert_group_member(const GroupMember& m) {
    auto s = db_.prepare(
        "INSERT OR REPLACE INTO group_members"
        "(group_id,contact_id,their_key_b_kem,their_key_b_sig,my_key_b_id,role,joined_at)"
        " VALUES(?,?,?,?,?,?,?)");
    s.bind_text(1, m.group_id);
    s.bind_text(2, m.contact_id);
    s.bind_blob(3, ByteSpan{m.their_key_b_kem.data(), m.their_key_b_kem.size()});
    s.bind_blob(4, ByteSpan{m.their_key_b_sig.data(), m.their_key_b_sig.size()});
    s.bind_text(5, m.my_key_b_id);
    s.bind_text(6, m.role);
    s.bind_int (7, m.joined_at);
    s.exec();
}

std::optional<GroupMember> MessageStore::get_group_member(
        const std::string& group_id,
        const std::string& contact_id) const {
    auto s = db_.prepare(
        "SELECT group_id,contact_id,their_key_b_kem,their_key_b_sig,my_key_b_id,role,joined_at"
        " FROM group_members WHERE group_id=? AND contact_id=?");
    s.bind_text(1, group_id);
    s.bind_text(2, contact_id);
    std::optional<GroupMember> out;
    s.query_one([&](const Row& r) {
        GroupMember m;
        m.group_id       = r.require_text(0);
        m.contact_id     = r.require_text(1);
        m.their_key_b_kem= r.require_blob(2);
        m.their_key_b_sig= r.require_blob(3);
        m.my_key_b_id    = r.require_text(4);
        m.role           = r.require_text(5);
        m.joined_at      = r.require_int(6);
        out = m;
    });
    return out;
}

std::vector<GroupMember> MessageStore::list_group_members(
        const std::string& group_id) const {
    auto s = db_.prepare(
        "SELECT group_id,contact_id,their_key_b_kem,their_key_b_sig,my_key_b_id,role,joined_at"
        " FROM group_members WHERE group_id=?");
    s.bind_text(1, group_id);
    std::vector<GroupMember> out;
    s.query([&](const Row& r) {
        GroupMember m;
        m.group_id       = r.require_text(0);
        m.contact_id     = r.require_text(1);
        m.their_key_b_kem= r.require_blob(2);
        m.their_key_b_sig= r.require_blob(3);
        m.my_key_b_id    = r.require_text(4);
        m.role           = r.require_text(5);
        m.joined_at      = r.require_int(6);
        out.push_back(std::move(m));
    });
    return out;
}

void MessageStore::remove_group_member(const std::string& group_id,
                                        const std::string& contact_id) {
    auto s = db_.prepare(
        "DELETE FROM group_members WHERE group_id=? AND contact_id=?");
    s.bind_text(1, group_id);
    s.bind_text(2, contact_id);
    s.exec();
}

// ── server_channels ───────────────────────────────────────────────────────────

void MessageStore::upsert_server_channel(const ServerChannel& c) {
    auto s = db_.prepare(
        "INSERT OR REPLACE INTO server_channels(id,server_id,name,type,created_at)"
        " VALUES(?,?,?,?,?)");
    s.bind_text(1, c.id);
    s.bind_text(2, c.server_id);
    s.bind_text(3, c.name);
    s.bind_text(4, c.type);
    s.bind_int (5, c.created_at);
    s.exec();
}

std::optional<ServerChannel> MessageStore::get_server_channel(
        const std::string& id) const {
    auto s = db_.prepare(
        "SELECT id,server_id,name,type,created_at FROM server_channels WHERE id=?");
    s.bind_text(1, id);
    std::optional<ServerChannel> out;
    s.query_one([&](const Row& r) {
        ServerChannel c;
        c.id         = r.require_text(0);
        c.server_id  = r.require_text(1);
        c.name       = r.require_text(2);
        c.type       = r.require_text(3);
        c.created_at = r.require_int(4);
        out = c;
    });
    return out;
}

std::vector<ServerChannel> MessageStore::list_server_channels(
        const std::string& server_id) const {
    auto s = db_.prepare(
        "SELECT id,server_id,name,type,created_at FROM server_channels WHERE server_id=?");
    s.bind_text(1, server_id);
    std::vector<ServerChannel> out;
    s.query([&](const Row& r) {
        ServerChannel c;
        c.id         = r.require_text(0);
        c.server_id  = r.require_text(1);
        c.name       = r.require_text(2);
        c.type       = r.require_text(3);
        c.created_at = r.require_int(4);
        out.push_back(std::move(c));
    });
    return out;
}

} // namespace sw::client
