#pragma once
#include <sw/types.hpp>
#include <sw/store/db.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sw::outbox {

enum class MsgStatus {
    PENDING   = 0,
    DELIVERED = 1,
    EXPIRED   = 2,
    CANCELLED = 3,
};

struct QueuedMessage {
    std::string message_id;
    std::string recipient_key_b_kem_pubkey_hex; // hex of ML-KEM-768 pubkey
    Bytes       delivery_frame;
    int32_t     priority        = 0;
    int64_t     enqueued_at_ms  = 0;
    int64_t     expires_at_ms   = 0;
    MsgStatus   status          = MsgStatus::PENDING;
    int32_t     attempt_count   = 0;
    int64_t     next_attempt_at = 0; // unix ms; 0 = passive wait
};

struct RecipientInbox {
    std::string message_id;
    Bytes       key_c_pubkey;
    Bytes       auth_cert;
};

struct SiblingOutbox {
    std::string device_id;
    Bytes       key_c_pubkey;
    Bytes       auth_cert;
    std::string channel_id;
    int64_t     last_seen_ms = 0;
};

struct InboxHint {
    std::string recipient_key_b_kem_pubkey_hex;
    Bytes       inbox_key_c_pubkey;
    std::string guard_node_id;
    std::string guard_endpoint;
    int64_t     session_token_expires = 0;
};

class OutboxStore {
public:
    explicit OutboxStore(const std::string& path);

    void init_schema();

    // ── queued_messages ──────────────────────────────────────────────────────
    bool insert_message(const QueuedMessage& msg);
    bool message_exists(const std::string& message_id) const;
    std::optional<QueuedMessage> get_message(const std::string& message_id) const;
    std::vector<QueuedMessage> list_pending() const;
    std::vector<QueuedMessage> list_due(int64_t now_ms) const;
    void set_status(const std::string& id, MsgStatus s);
    void update_attempt(const std::string& id, int32_t attempt_count,
                        int64_t next_attempt_at_ms);
    void delete_message(const std::string& id);
    void expire_messages(int64_t now_ms);

    // ── recipient_inboxes ────────────────────────────────────────────────────
    void add_recipient_inbox(const RecipientInbox& r);
    std::vector<RecipientInbox> get_recipient_inboxes(const std::string& message_id) const;
    bool is_valid_recipient_inbox(const std::string& message_id,
                                   const Bytes& key_c_pubkey) const;

    // ── sibling_outboxes ─────────────────────────────────────────────────────
    void upsert_sibling(const SiblingOutbox& s);
    void remove_sibling(const std::string& device_id);
    std::vector<SiblingOutbox> list_siblings() const;
    void set_sibling_channel(const std::string& device_id, const std::string& channel_id);

    // ── inbox_hints ──────────────────────────────────────────────────────────
    void upsert_inbox_hint(const InboxHint& h);
    std::vector<InboxHint> get_hints(const std::string& recipient_key_b_hex) const;

    // ── auth cert ────────────────────────────────────────────────────────────
    void set_auth_cert(Bytes key_c_pubkey, Bytes key_c_privkey, Bytes auth_cert);
    struct AuthCreds { Bytes key_c_pubkey; Bytes key_c_privkey; Bytes auth_cert; };
    std::optional<AuthCreds> get_auth_creds() const;

private:
    mutable sw::store::Db db_;
};

} // namespace sw::outbox
