#pragma once
#include <sw/types.hpp>
#include <sw/store/db.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sw::inbox {

struct StoredMessage {
    std::string message_id;       // 16-byte hex
    std::string sender_id;        // 32-byte hex of SHA3-256(Key A pubkey)
    Bytes       delivery_frame;   // opaque ciphertext blob
    std::string persistence;      // "store" | "pass_through"
    bool        delivered_to_client = false;
    bool        replicated          = false;
    int64_t     received_at_ms      = 0;
    int64_t     expires_at          = 0;  // unix seconds; 0 = never
};

struct SiblingInbox {
    std::string device_id;        // hex(SHA3-256(key_c_pubkey))
    Bytes       key_c_pubkey;
    Bytes       auth_cert;
    std::string channel_id;       // active AnonRouter channel, empty if none
    int64_t     last_seen_ms      = 0;
};

struct KnownOutbox {
    Bytes   key_c_pubkey;
    Bytes   auth_cert;
    int64_t expires_at = 0;       // unix seconds
};

struct DhtCredentials {
    Bytes   key_c_pubkey;
    Bytes   key_c_privkey;
    Bytes   auth_cert;
    Bytes   delegation_cert;      // Key A-signed, authorises key_c to sign DHT records
};

class InboxStore {
public:
    explicit InboxStore(const std::string& path);

    // ── Schema ──────────────────────────────────────────────────────────────
    void init_schema();

    // ── stored_messages ─────────────────────────────────────────────────────
    bool insert_message(const StoredMessage& msg);
    bool message_exists(const std::string& message_id) const;
    std::optional<StoredMessage> get_message(const std::string& message_id) const;
    std::vector<StoredMessage> get_pending(bool undelivered_only) const;
    void mark_delivered(const std::string& message_id, int64_t expires_at);
    void delete_message(const std::string& message_id);
    void delete_expired(int64_t now_s);

    // ── sibling_inboxes ──────────────────────────────────────────────────────
    void upsert_sibling(const SiblingInbox& s);
    void remove_sibling(const std::string& device_id);
    std::vector<SiblingInbox> list_siblings() const;
    void set_sibling_channel(const std::string& device_id, const std::string& channel_id);
    void set_sibling_replicated(const std::string& message_id, const std::string& device_id);

    // ── dht_credentials ──────────────────────────────────────────────────────
    std::optional<DhtCredentials> get_dht_credentials() const;
    void set_dht_credentials(const DhtCredentials& creds);

    // ── known_outboxes ───────────────────────────────────────────────────────
    void replace_known_outboxes(const std::vector<KnownOutbox>& list);
    std::vector<KnownOutbox> list_known_outboxes() const;

    // ── allowed_senders ──────────────────────────────────────────────────────
    void replace_allowed_senders(const std::vector<std::string>& sender_id_hexes);
    bool is_allowed_sender(const std::string& sender_id_hex) const;

    // ── cr_guard_rate_limit ───────────────────────────────────────────────────
    // Returns current frame count in the current hour window.
    int  cr_guard_count_this_hour(int64_t now_s) const;
    void cr_guard_record(int64_t now_s);

    // ── retention ────────────────────────────────────────────────────────────
    void set_retention_days(int days);
    int  get_retention_days() const;

private:
    mutable sw::store::Db db_;
    int retention_days_ = 7;
};

} // namespace sw::inbox
