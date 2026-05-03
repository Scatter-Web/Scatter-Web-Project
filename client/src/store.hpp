#pragma once
#include <sw/types.hpp>
#include <sw/store/db.hpp>
#include <optional>
#include <string>
#include <vector>

namespace sw::client {

using namespace sw::store;

// ── Data types ────────────────────────────────────────────────────────────────

struct Conversation {
    std::string id;
    std::string type;          // "dm" | "group" | "server_channel"
    std::string display_name;
    std::string contact_id;    // DM only
    std::string group_id;      // group/server_channel only
    int64_t     last_read_seq = 0;
    int64_t     created_at    = 0;
};

struct StoredMessage {
    std::string id;
    std::string conversation_id;
    Bytes       sender_id;     // 32 bytes SHA3-256(sender Key A)
    int64_t     seq = 0;
    std::string content_type;
    std::string text;          // decrypted plaintext (empty for attachments)
    Bytes       ciphertext;    // raw delivery_frame bytes
    int64_t     sent_at    = 0;
    int64_t     received_at = 0;
    std::string status;        // "pending" | "sent" | "delivered" | "read" | "failed"
    std::string reply_to_id;
};

struct Reaction {
    std::string message_id;
    std::string contact_id;
    std::string emoji;
    int64_t     added_at = 0;
};

struct Contact {
    std::string id;            // hex(SHA3-256(key_a_pubkey))
    std::string display_name;
    Bytes       key_a_pubkey;
    Bytes       their_dm_key_b_kem;
    Bytes       their_dm_key_b_sig;
    std::string my_key_b_id;
    Bytes       their_key_c_pubkeys; // CBOR list
    int64_t     added_at = 0;
    std::string status;        // "pending" | "active" | "blocked"
};

struct Group {
    std::string id;
    std::string name;
    std::string type;    // "group" | "server"
    std::string my_role; // "owner" | "admin" | "member"
    int64_t     created_at = 0;
};

struct GroupMember {
    std::string group_id;
    std::string contact_id;
    Bytes       their_key_b_kem;
    Bytes       their_key_b_sig;
    std::string my_key_b_id; // empty if not self
    std::string role;
    int64_t     joined_at = 0;
};

struct ServerChannel {
    std::string id;
    std::string server_id;
    std::string name;
    std::string type;       // "text" | "voice" | "video"
    int64_t     created_at = 0;
};

struct KnownCert {
    Bytes       fingerprint; // 32 bytes SHA3-256(auth_cert)
    Bytes       auth_cert;
    std::string owner_id;
    int64_t     cached_at = 0;
};

// ── MessageStore ──────────────────────────────────────────────────────────────

class MessageStore {
public:
    explicit MessageStore(const std::string& path);

    // ── conversations ────────────────────────────────────────────────────────
    void                     upsert_conversation(const Conversation& c);
    std::optional<Conversation> get_conversation(const std::string& id) const;
    std::vector<Conversation>   list_conversations() const;
    void                     update_last_read(const std::string& conv_id, int64_t seq);

    // ── messages ─────────────────────────────────────────────────────────────
    bool                     insert_message(const StoredMessage& m);
    std::optional<StoredMessage> get_message(const std::string& id) const;
    // Returns up to `limit` messages before `before_seq` (0 = no filter).
    std::vector<StoredMessage> list_messages(const std::string& conv_id,
                                              int64_t before_seq, int limit) const;
    void                     update_message_status(const std::string& id,
                                                    const std::string& status);
    void                     delete_message(const std::string& id);
    void                     update_message_text(const std::string& id,
                                                  const std::string& text);
    int64_t                  next_seq(const std::string& conv_id) const;

    // ── known_certs ──────────────────────────────────────────────────────────
    std::optional<KnownCert> get_cert(const Bytes& fingerprint) const;
    void                     insert_cert(const KnownCert& c);

    // ── reactions ────────────────────────────────────────────────────────────
    void                   upsert_reaction(const Reaction& r);
    void                   delete_reaction(const std::string& msg_id,
                                            const std::string& contact_id,
                                            const std::string& emoji);
    std::vector<Reaction>  get_reactions(const std::string& msg_id) const;

    // ── contacts ─────────────────────────────────────────────────────────────
    bool                   insert_contact(const Contact& c);
    std::optional<Contact> get_contact(const std::string& id) const;
    std::vector<Contact>   list_contacts() const;
    void                   update_contact(const Contact& c);
    void                   set_contact_status(const std::string& id,
                                               const std::string& status);

    // ── groups ───────────────────────────────────────────────────────────────
    void                  upsert_group(const Group& g);
    std::optional<Group>  get_group(const std::string& id) const;
    std::vector<Group>    list_groups() const;

    // ── group_members ────────────────────────────────────────────────────────
    void                      upsert_group_member(const GroupMember& m);
    std::optional<GroupMember> get_group_member(const std::string& group_id,
                                                 const std::string& contact_id) const;
    std::vector<GroupMember>  list_group_members(const std::string& group_id) const;
    void                      remove_group_member(const std::string& group_id,
                                                   const std::string& contact_id);

    // ── server_channels ──────────────────────────────────────────────────────
    void                        upsert_server_channel(const ServerChannel& c);
    std::optional<ServerChannel> get_server_channel(const std::string& id) const;
    std::vector<ServerChannel>  list_server_channels(const std::string& server_id) const;

    // ── server_roles ─────────────────────────────────────────────────────────
    void set_server_role(const std::string& server_id,
                          const std::string& contact_id,
                          const std::string& role,
                          int64_t assigned_at);

private:
    mutable Db db_;
    void init_schema();
};

} // namespace sw::client
