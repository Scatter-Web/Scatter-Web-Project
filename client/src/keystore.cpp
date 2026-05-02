#include "keystore.hpp"
#include <sw/crypto/kdf.hpp>
#include <sw/crypto/aes_gcm.hpp>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <vector>
#include <sodium.h>

namespace sw::client {

using namespace sw::crypto;

// File format: [12B nonce][16B tag][ciphertext]
static constexpr size_t NONCE_OFF = 0;
static constexpr size_t TAG_OFF   = 12;
static constexpr size_t CT_OFF    = 28;

Keystore::Keystore(std::string keystore_path, std::string salt_path)
    : keystore_path_(std::move(keystore_path))
    , salt_path_(std::move(salt_path))
{}

Keystore::~Keystore() {
    if (db_) sqlite3_close(db_);
    sodium_memzero(master_key_.data(), master_key_.size());
}

Key32 Keystore::derive_key(const std::string& passphrase) {
    // Read or create salt.
    Bytes salt(32, 0);
    std::ifstream sf(salt_path_, std::ios::binary);
    if (sf) {
        sf.read(reinterpret_cast<char*>(salt.data()), 32);
    } else {
        randombytes_buf(salt.data(), 32);
        std::ofstream osf(salt_path_, std::ios::binary | std::ios::trunc);
        if (!osf) throw std::runtime_error("cannot write salt: " + salt_path_);
        osf.write(reinterpret_cast<const char*>(salt.data()), 32);
    }
    return argon2id(passphrase, ByteSpan{salt.data(), 32});
}

void Keystore::unlock(const std::string& passphrase) {
    if (db_) throw std::runtime_error("already unlocked");
    Key32 mk = derive_key(passphrase);
    load_from_disk(mk);
    master_key_     = mk;
    have_master_key_ = true;
}

void Keystore::lock() {
    if (!db_) return;
    save();
    sqlite3_close(db_);
    db_ = nullptr;
    sodium_memzero(master_key_.data(), master_key_.size());
    have_master_key_ = false;
}

void Keystore::change_passphrase(const std::string& old_pass,
                                  const std::string& new_pass) {
    if (!db_) throw std::runtime_error("keystore locked");
    Key32 old_mk = derive_key(old_pass);
    if (old_mk != master_key_)
        throw std::runtime_error("wrong passphrase");

    // Remove old salt so derive_key creates a new one.
    std::remove(salt_path_.c_str());
    Key32 new_mk = derive_key(new_pass);
    write_to_disk(new_mk);
    master_key_ = new_mk;
}

void Keystore::load_from_disk(const Key32& mk) {
    std::ifstream f(keystore_path_, std::ios::binary | std::ios::ate);
    if (!f) {
        // First launch — create empty DB in memory.
        int rc = sqlite3_open(":memory:", &db_);
        if (rc != SQLITE_OK) throw std::runtime_error("sqlite3_open failed");
        init_schema();
        write_to_disk(mk);
        return;
    }

    auto file_size = static_cast<size_t>(f.tellg());
    if (file_size < CT_OFF)
        throw std::runtime_error("keystore file too small");

    f.seekg(0);
    Bytes file_bytes(file_size);
    f.read(reinterpret_cast<char*>(file_bytes.data()), static_cast<std::streamsize>(file_size));

    AesNonce nonce;
    AesTag   tag;
    std::copy(file_bytes.begin()          , file_bytes.begin() + 12, nonce.begin());
    std::copy(file_bytes.begin() + TAG_OFF, file_bytes.begin() + CT_OFF, tag.begin());

    Bytes ct(file_bytes.begin() + CT_OFF, file_bytes.end());
    AesKey key;
    std::copy(mk.begin(), mk.end(), key.begin());

    Bytes plaintext;
    try {
        plaintext = aes_decrypt(key, nonce, ByteSpan{ct.data(), ct.size()}, tag);
    } catch (...) {
        throw std::runtime_error("wrong passphrase or corrupt keystore");
    }

    int rc = sqlite3_open(":memory:", &db_);
    if (rc != SQLITE_OK) throw std::runtime_error("sqlite3_open failed");

    // sqlite3_deserialize takes ownership of the buffer; allocate via sqlite3_malloc.
    uint8_t* db_copy = static_cast<uint8_t*>(sqlite3_malloc64(plaintext.size()));
    if (!db_copy) throw std::runtime_error("sqlite3_malloc64 failed");
    std::copy(plaintext.begin(), plaintext.end(), db_copy);
    rc = sqlite3_deserialize(db_, "main",
                             db_copy,
                             static_cast<sqlite3_int64>(plaintext.size()),
                             static_cast<sqlite3_int64>(plaintext.size()),
                             SQLITE_DESERIALIZE_FREEONCLOSE |
                             SQLITE_DESERIALIZE_RESIZEABLE);
    if (rc != SQLITE_OK) {
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("sqlite3_deserialize failed");
    }

    init_schema();
}

void Keystore::save() {
    if (!db_ || !have_master_key_) return;
    write_to_disk(master_key_);
}

void Keystore::write_to_disk(const Key32& mk) {
    sqlite3_int64 db_size = 0;
    uint8_t* db_buf = sqlite3_serialize(db_, "main", &db_size, 0);
    if (!db_buf && db_size > 0)
        throw std::runtime_error("sqlite3_serialize failed");

    Bytes plaintext;
    if (db_buf) {
        plaintext.assign(db_buf, db_buf + db_size);
        sqlite3_free(db_buf);
    }

    // Read current nonce from file to increment it.
    AesNonce nonce{};
    std::ifstream f(keystore_path_, std::ios::binary);
    if (f) {
        f.read(reinterpret_cast<char*>(nonce.data()), 12);
        // Increment as big-endian 96-bit integer.
        for (int i = 11; i >= 0; --i) {
            if (++nonce[i]) break;
        }
    } else {
        nonce[11] = 1;
    }

    Bytes ct(plaintext.size());
    AesTag tag{};
    if (crypto_aead_aes256gcm_encrypt_detached(
            ct.data(), tag.data(), nullptr,
            plaintext.data(), plaintext.size(),
            nullptr, 0,
            nullptr,
            nonce.data(),
            mk.data()) != 0)
        throw std::runtime_error("aes_encrypt failed");

    std::ofstream of(keystore_path_, std::ios::binary | std::ios::trunc);
    if (!of) throw std::runtime_error("cannot write keystore: " + keystore_path_);
    of.write(reinterpret_cast<const char*>(nonce.data()), 12);
    of.write(reinterpret_cast<const char*>(tag.data()),   16);
    of.write(reinterpret_cast<const char*>(ct.data()),    static_cast<std::streamsize>(ct.size()));
}

void Keystore::init_schema() {
    const char* ddl = R"(
        CREATE TABLE IF NOT EXISTS key_a (
            id         INTEGER PRIMARY KEY CHECK(id=1),
            pubkey     BLOB NOT NULL,
            privkey    BLOB NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS key_b (
            id           TEXT PRIMARY KEY,
            relationship TEXT NOT NULL,
            kem_pubkey   BLOB NOT NULL,
            kem_privkey  BLOB NOT NULL,
            sig_pubkey   BLOB NOT NULL,
            sig_privkey  BLOB NOT NULL,
            created_at   INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS key_b_cr (
            id         INTEGER PRIMARY KEY CHECK(id=1),
            kem_pubkey BLOB NOT NULL,
            kem_privkey BLOB NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS key_c_issued (
            device_id      TEXT PRIMARY KEY,
            device_type    TEXT NOT NULL,
            device_label   TEXT NOT NULL DEFAULT '',
            key_c_pubkey   BLOB NOT NULL,
            auth_cert      BLOB NOT NULL,
            dht_deleg_cert BLOB NOT NULL DEFAULT '',
            issued_at      INTEGER NOT NULL,
            expires_at     INTEGER NOT NULL,
            revoked        INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS key_d_prekeys (
            id          TEXT PRIMARY KEY,
            key_b_id    TEXT NOT NULL,
            kem_pubkey  BLOB NOT NULL,
            kem_privkey BLOB NOT NULL,
            consumed    INTEGER NOT NULL DEFAULT 0,
            created_at  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS key_e_ratchet (
            id            TEXT PRIMARY KEY,
            ratchet_state BLOB NOT NULL,
            updated_at    INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS key_f_sender (
            id         TEXT PRIMARY KEY,
            group_id   TEXT NOT NULL,
            contact_id TEXT NOT NULL,
            sym_key    BLOB NOT NULL,
            generation INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ks_config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    )";
    char* errmsg = nullptr;
    int rc = sqlite3_exec(db_, ddl, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown";
        sqlite3_free(errmsg);
        throw std::runtime_error("keystore schema error: " + err);
    }
}

// ── key_a ─────────────────────────────────────────────────────────────────────

std::optional<KeyA> Keystore::get_key_a() const {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "SELECT pubkey,privkey,created_at FROM key_a WHERE id=1",
        -1, &stmt, nullptr);
    std::optional<KeyA> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        KeyA k;
        const uint8_t* pb = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 0));
        const uint8_t* prb = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 1));
        std::copy(pb,  pb  + MLDSA65_PUBKEY_BYTES,  k.pubkey.begin());
        std::copy(prb, prb + MLDSA65_PRIVKEY_BYTES, k.privkey.begin());
        k.created_at = sqlite3_column_int64(stmt, 2);
        result = k;
    }
    sqlite3_finalize(stmt);
    return result;
}

void Keystore::set_key_a(const KeyA& k) {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO key_a(id,pubkey,privkey,created_at) VALUES(1,?,?,?)",
        -1, &stmt, nullptr);
    sqlite3_bind_blob(stmt, 1, k.pubkey.data(),  MLDSA65_PUBKEY_BYTES,  SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, k.privkey.data(), MLDSA65_PRIVKEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, k.created_at);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ── key_b ─────────────────────────────────────────────────────────────────────

static KeyB row_to_key_b(sqlite3_stmt* s) {
    KeyB k;
    k.id           = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
    k.relationship = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
    const uint8_t* kp  = static_cast<const uint8_t*>(sqlite3_column_blob(s, 2));
    const uint8_t* kpr = static_cast<const uint8_t*>(sqlite3_column_blob(s, 3));
    const uint8_t* sp  = static_cast<const uint8_t*>(sqlite3_column_blob(s, 4));
    const uint8_t* spr = static_cast<const uint8_t*>(sqlite3_column_blob(s, 5));
    std::copy(kp,  kp  + MLKEM768_PUBKEY_BYTES,  k.kem_pubkey.begin());
    std::copy(kpr, kpr + MLKEM768_PRIVKEY_BYTES, k.kem_privkey.begin());
    std::copy(sp,  sp  + MLDSA65_PUBKEY_BYTES,  k.sig_pubkey.begin());
    std::copy(spr, spr + MLDSA65_PRIVKEY_BYTES, k.sig_privkey.begin());
    k.created_at = sqlite3_column_int64(s, 6);
    return k;
}

std::optional<KeyB> Keystore::get_key_b(const std::string& id) const {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "SELECT id,relationship,kem_pubkey,kem_privkey,sig_pubkey,sig_privkey,created_at"
        " FROM key_b WHERE id=?", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_STATIC);
    std::optional<KeyB> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) result = row_to_key_b(stmt);
    sqlite3_finalize(stmt);
    return result;
}

std::vector<KeyB> Keystore::list_key_b() const {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "SELECT id,relationship,kem_pubkey,kem_privkey,sig_pubkey,sig_privkey,created_at"
        " FROM key_b", -1, &stmt, nullptr);
    std::vector<KeyB> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(row_to_key_b(stmt));
    sqlite3_finalize(stmt);
    return out;
}

void Keystore::insert_key_b(const KeyB& k) {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "INSERT OR IGNORE INTO key_b"
        "(id,relationship,kem_pubkey,kem_privkey,sig_pubkey,sig_privkey,created_at)"
        " VALUES(?,?,?,?,?,?,?)",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, k.id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, k.relationship.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, k.kem_pubkey.data(),  MLKEM768_PUBKEY_BYTES,  SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, k.kem_privkey.data(), MLKEM768_PRIVKEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, k.sig_pubkey.data(),  MLDSA65_PUBKEY_BYTES,   SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 6, k.sig_privkey.data(), MLDSA65_PRIVKEY_BYTES,  SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, k.created_at);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ── key_b_cr ──────────────────────────────────────────────────────────────────

std::optional<KeyBCr> Keystore::get_key_b_cr() const {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "SELECT kem_pubkey,kem_privkey,created_at FROM key_b_cr WHERE id=1",
        -1, &stmt, nullptr);
    std::optional<KeyBCr> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        KeyBCr k;
        const uint8_t* kp  = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 0));
        const uint8_t* kpr = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 1));
        std::copy(kp,  kp  + MLKEM768_PUBKEY_BYTES,  k.kem_pubkey.begin());
        std::copy(kpr, kpr + MLKEM768_PRIVKEY_BYTES, k.kem_privkey.begin());
        k.created_at = sqlite3_column_int64(stmt, 2);
        result = k;
    }
    sqlite3_finalize(stmt);
    return result;
}

void Keystore::set_key_b_cr(const KeyBCr& k) {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO key_b_cr(id,kem_pubkey,kem_privkey,created_at)"
        " VALUES(1,?,?,?)",
        -1, &stmt, nullptr);
    sqlite3_bind_blob(stmt, 1, k.kem_pubkey.data(),  MLKEM768_PUBKEY_BYTES,  SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, k.kem_privkey.data(), MLKEM768_PRIVKEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, k.created_at);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ── key_c_issued ──────────────────────────────────────────────────────────────

static KeyCIssued row_to_key_c(sqlite3_stmt* s) {
    KeyCIssued k;
    k.device_id   = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
    k.device_type = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
    k.device_label= reinterpret_cast<const char*>(sqlite3_column_text(s, 2));
    const uint8_t* kp = static_cast<const uint8_t*>(sqlite3_column_blob(s, 3));
    std::copy(kp, kp + MLDSA65_PUBKEY_BYTES, k.key_c_pubkey.begin());
    const uint8_t* cert = static_cast<const uint8_t*>(sqlite3_column_blob(s, 4));
    int cert_len = sqlite3_column_bytes(s, 4);
    k.auth_cert.assign(cert, cert + cert_len);
    const uint8_t* del = static_cast<const uint8_t*>(sqlite3_column_blob(s, 5));
    int del_len = sqlite3_column_bytes(s, 5);
    k.dht_deleg_cert.assign(del, del + del_len);
    k.issued_at = sqlite3_column_int64(s, 6);
    k.expires_at = sqlite3_column_int64(s, 7);
    k.revoked = sqlite3_column_int(s, 8) != 0;
    return k;
}

void Keystore::insert_key_c(const KeyCIssued& k) {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO key_c_issued"
        "(device_id,device_type,device_label,key_c_pubkey,auth_cert,dht_deleg_cert,"
        "issued_at,expires_at,revoked)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, k.device_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, k.device_type.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, k.device_label.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, k.key_c_pubkey.data(), MLDSA65_PUBKEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, k.auth_cert.data(), static_cast<int>(k.auth_cert.size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 6, k.dht_deleg_cert.data(), static_cast<int>(k.dht_deleg_cert.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, k.issued_at);
    sqlite3_bind_int64(stmt, 8, k.expires_at);
    sqlite3_bind_int(stmt, 9, k.revoked ? 1 : 0);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::optional<KeyCIssued> Keystore::get_key_c(const std::string& device_id) const {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "SELECT device_id,device_type,device_label,key_c_pubkey,auth_cert,dht_deleg_cert,"
        "issued_at,expires_at,revoked"
        " FROM key_c_issued WHERE device_id=?",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, device_id.c_str(), -1, SQLITE_STATIC);
    std::optional<KeyCIssued> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) result = row_to_key_c(stmt);
    sqlite3_finalize(stmt);
    return result;
}

std::vector<KeyCIssued> Keystore::list_key_c() const {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "SELECT device_id,device_type,device_label,key_c_pubkey,auth_cert,dht_deleg_cert,"
        "issued_at,expires_at,revoked FROM key_c_issued",
        -1, &stmt, nullptr);
    std::vector<KeyCIssued> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) out.push_back(row_to_key_c(stmt));
    sqlite3_finalize(stmt);
    return out;
}

void Keystore::revoke_key_c(const std::string& device_id) {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "UPDATE key_c_issued SET revoked=1 WHERE device_id=?",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, device_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void Keystore::update_key_c_cert(const std::string& device_id,
                                  const Bytes& auth_cert,
                                  int64_t expires_at) {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "UPDATE key_c_issued SET auth_cert=?, expires_at=? WHERE device_id=?",
        -1, &stmt, nullptr);
    sqlite3_bind_blob(stmt, 1, auth_cert.data(), static_cast<int>(auth_cert.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, expires_at);
    sqlite3_bind_text(stmt, 3, device_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ── key_d_prekeys ─────────────────────────────────────────────────────────────

void Keystore::insert_prekey(const KeyDPrekey& k) {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "INSERT OR IGNORE INTO key_d_prekeys"
        "(id,key_b_id,kem_pubkey,kem_privkey,consumed,created_at)"
        " VALUES(?,?,?,?,?,?)",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, k.id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, k.key_b_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, k.kem_pubkey.data(),  MLKEM768_PUBKEY_BYTES,  SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, k.kem_privkey.data(), MLKEM768_PRIVKEY_BYTES, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, k.consumed ? 1 : 0);
    sqlite3_bind_int64(stmt, 6, k.created_at);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::optional<KeyDPrekey> Keystore::get_available_prekey(
        const std::string& key_b_id) const {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "SELECT id,key_b_id,kem_pubkey,kem_privkey,consumed,created_at"
        " FROM key_d_prekeys WHERE key_b_id=? AND consumed=0 LIMIT 1",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, key_b_id.c_str(), -1, SQLITE_STATIC);
    std::optional<KeyDPrekey> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        KeyDPrekey k;
        k.id       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        k.key_b_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const uint8_t* kp  = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 2));
        const uint8_t* kpr = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 3));
        std::copy(kp,  kp  + MLKEM768_PUBKEY_BYTES,  k.kem_pubkey.begin());
        std::copy(kpr, kpr + MLKEM768_PRIVKEY_BYTES, k.kem_privkey.begin());
        k.consumed   = sqlite3_column_int(stmt, 4) != 0;
        k.created_at = sqlite3_column_int64(stmt, 5);
        result = k;
    }
    sqlite3_finalize(stmt);
    return result;
}

void Keystore::consume_prekey(const std::string& id) {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "UPDATE key_d_prekeys SET consumed=1 WHERE id=?",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

int Keystore::count_prekeys(const std::string& key_b_id) const {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM key_d_prekeys WHERE key_b_id=? AND consumed=0",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, key_b_id.c_str(), -1, SQLITE_STATIC);
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

std::vector<KeyDPrekey> Keystore::list_prekeys(const std::string& key_b_id) const {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "SELECT id,key_b_id,kem_pubkey,kem_privkey,consumed,created_at"
        " FROM key_d_prekeys WHERE key_b_id=? AND consumed=0",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, key_b_id.c_str(), -1, SQLITE_STATIC);
    std::vector<KeyDPrekey> out;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        KeyDPrekey k;
        k.id       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        k.key_b_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const uint8_t* kp  = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 2));
        const uint8_t* kpr = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 3));
        std::copy(kp,  kp  + MLKEM768_PUBKEY_BYTES,  k.kem_pubkey.begin());
        std::copy(kpr, kpr + MLKEM768_PRIVKEY_BYTES, k.kem_privkey.begin());
        k.consumed   = sqlite3_column_int(stmt, 4) != 0;
        k.created_at = sqlite3_column_int64(stmt, 5);
        out.push_back(k);
    }
    sqlite3_finalize(stmt);
    return out;
}

// ── key_e_ratchet ─────────────────────────────────────────────────────────────

Bytes Keystore::get_ratchet_state(const std::string& conv_id) const {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "SELECT ratchet_state FROM key_e_ratchet WHERE id=?",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, conv_id.c_str(), -1, SQLITE_STATIC);
    Bytes result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const uint8_t* p = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 0));
        int len = sqlite3_column_bytes(stmt, 0);
        result.assign(p, p + len);
    }
    sqlite3_finalize(stmt);
    return result;
}

void Keystore::set_ratchet_state(const std::string& conv_id, const Bytes& state) {
    sqlite3_stmt* stmt = nullptr;
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO key_e_ratchet(id,ratchet_state,updated_at) VALUES(?,?,?)",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, conv_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, state.data(), static_cast<int>(state.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, now);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

bool Keystore::has_ratchet_state(const std::string& conv_id) const {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "SELECT 1 FROM key_e_ratchet WHERE id=?",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, conv_id.c_str(), -1, SQLITE_STATIC);
    bool found = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    return found;
}

// ── key_f_sender ──────────────────────────────────────────────────────────────

std::optional<Keystore::SenderKey> Keystore::get_sender_key(
        const std::string& group_id,
        const std::string& contact_id) const {
    std::string compound_id = group_id + ":" + contact_id;
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "SELECT group_id,contact_id,sym_key,generation,created_at"
        " FROM key_f_sender WHERE id=?",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, compound_id.c_str(), -1, SQLITE_STATIC);
    std::optional<SenderKey> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        SenderKey sk;
        sk.group_id   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        sk.contact_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const uint8_t* kp = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 2));
        std::copy(kp, kp + 32, sk.sym_key.begin());
        sk.generation = static_cast<uint32_t>(sqlite3_column_int64(stmt, 3));
        sk.created_at = sqlite3_column_int64(stmt, 4);
        result = sk;
    }
    sqlite3_finalize(stmt);
    return result;
}

void Keystore::set_sender_key(const SenderKey& sk) {
    std::string compound_id = sk.group_id + ":" + sk.contact_id;
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO key_f_sender"
        "(id,group_id,contact_id,sym_key,generation,created_at)"
        " VALUES(?,?,?,?,?,?)",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, compound_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, sk.group_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, sk.contact_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, sk.sym_key.data(), 32, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, static_cast<int64_t>(sk.generation));
    sqlite3_bind_int64(stmt, 6, sk.created_at);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ── config ────────────────────────────────────────────────────────────────────

std::string Keystore::get_config(const std::string& key) const {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "SELECT value FROM ks_config WHERE key=?",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    std::string result;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        result = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    sqlite3_finalize(stmt);
    return result;
}

void Keystore::set_config(const std::string& key, const std::string& val) {
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO ks_config(key,value) VALUES(?,?)",
        -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, val.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

} // namespace sw::client
