#pragma once
#include <sw/types.hpp>
#include <sw/crypto/mlkem.hpp>
#include <sw/crypto/mldsa.hpp>
#include <optional>
#include <string>
#include <vector>
#include <sqlite3.h>

namespace sw::client {

// ── Data types ────────────────────────────────────────────────────────────────

struct KeyA {
    crypto::DsaPubKey  pubkey;
    crypto::DsaPrivKey privkey;
    int64_t            created_at;
};

struct KeyB {
    std::string            id;          // relationship_id = hex(SHA3-256(relationship_string))
    std::string            relationship;
    crypto::KemPubKey      kem_pubkey;
    crypto::KemPrivKey     kem_privkey;
    crypto::DsaPubKey      sig_pubkey;
    crypto::DsaPrivKey     sig_privkey;
    int64_t                created_at;
};

struct KeyBCr {
    crypto::KemPubKey  kem_pubkey;
    crypto::KemPrivKey kem_privkey;
    int64_t            created_at;
};

struct KeyCIssued {
    std::string        device_id;    // hex(SHA3-256(key_c_pubkey))
    std::string        device_type;  // "inbox" | "outbox"
    std::string        device_label;
    crypto::DsaPubKey  key_c_pubkey;
    crypto::DsaPrivKey key_c_privkey;
    Bytes              auth_cert;
    Bytes              dht_deleg_cert; // empty for outbox
    int64_t            issued_at;
    int64_t            expires_at;
    bool               revoked = false;
};

struct KeyDPrekey {
    std::string       id;           // hex(SHA3-256(pubkey))
    std::string       key_b_id;
    crypto::KemPubKey kem_pubkey;
    crypto::KemPrivKey kem_privkey; // zeroed after consumption
    bool              consumed = false;
    int64_t           created_at;
};

// ── Keystore ──────────────────────────────────────────────────────────────────

// AES-GCM encrypted SQLite database stored on disk.
// File format: [12B nonce][16B GCM tag][ciphertext = raw SQLite bytes]
class Keystore {
public:
    Keystore(std::string keystore_path, std::string salt_path);
    ~Keystore();

    // Decrypt and load. Throws on bad passphrase.
    void unlock(const std::string& passphrase);

    // Encrypt and persist to disk; wipe key material from memory.
    void lock();

    // Re-encrypt on disk with a new passphrase (replaces salt too).
    void change_passphrase(const std::string& old_pass, const std::string& new_pass);

    bool is_unlocked() const noexcept { return db_ != nullptr; }

    // ── key_a ────────────────────────────────────────────────────────────────
    std::optional<KeyA> get_key_a() const;
    void                set_key_a(const KeyA& k);

    // ── key_b ────────────────────────────────────────────────────────────────
    std::optional<KeyB>  get_key_b(const std::string& id) const;
    std::vector<KeyB>    list_key_b() const;
    void                 insert_key_b(const KeyB& k);

    // ── key_b_contact_request ────────────────────────────────────────────────
    std::optional<KeyBCr> get_key_b_cr() const;
    void                  set_key_b_cr(const KeyBCr& k);

    // ── key_c_issued ─────────────────────────────────────────────────────────
    void                    insert_key_c(const KeyCIssued& k);
    std::optional<KeyCIssued> get_key_c(const std::string& device_id) const;
    std::vector<KeyCIssued> list_key_c() const;
    void                    revoke_key_c(const std::string& device_id);
    void                    update_key_c_cert(const std::string& device_id,
                                              const Bytes& auth_cert,
                                              int64_t expires_at);

    // ── key_d_prekeys ────────────────────────────────────────────────────────
    void                    insert_prekey(const KeyDPrekey& k);
    std::optional<KeyDPrekey> get_available_prekey(const std::string& key_b_id) const;
    void                    consume_prekey(const std::string& id);
    int                     count_prekeys(const std::string& key_b_id) const;
    std::vector<KeyDPrekey> list_prekeys(const std::string& key_b_id) const;

    // ── key_e_ratchet ────────────────────────────────────────────────────────
    Bytes                   get_ratchet_state(const std::string& conv_id) const;
    void                    set_ratchet_state(const std::string& conv_id, const Bytes& state);
    bool                    has_ratchet_state(const std::string& conv_id) const;

    // ── key_f_sender ─────────────────────────────────────────────────────────
    struct SenderKey {
        std::string group_id;
        std::string contact_id;
        Key32       sym_key;
        uint32_t    generation;
        int64_t     created_at;
    };
    std::optional<SenderKey> get_sender_key(const std::string& group_id,
                                             const std::string& contact_id) const;
    void                     set_sender_key(const SenderKey& sk);

    // ── config ───────────────────────────────────────────────────────────────
    std::string get_config(const std::string& key) const;
    void        set_config(const std::string& key, const std::string& val);

    // Flush in-memory DB back to encrypted file on disk.
    void save();

private:
    std::string keystore_path_;
    std::string salt_path_;
    sqlite3*    db_    = nullptr;
    Key32       master_key_{};
    bool        have_master_key_ = false;

    void init_schema();
    void load_from_disk(const Key32& master_key);
    void write_to_disk(const Key32& master_key);
    Key32 derive_key(const std::string& passphrase);
};

} // namespace sw::client
