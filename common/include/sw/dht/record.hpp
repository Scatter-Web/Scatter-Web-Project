#pragma once
#include <sw/types.hpp>
#include <sw/crypto/mlkem.hpp>
#include <sw/crypto/mldsa.hpp>
#include <cstdint>
#include <string>

// DHT record construction and parsing.
//
// Guard record (lookup key rotates every 30 min):
//   dht_key  = SHA3-256(key_b_pub || timeslot)
//   aead_key = SHAKE-256(key_b_pub || timeslot || "guard_record", 32)
//   plaintext encrypted with AES-256-GCM, outer signed with Key A (Client) or Key C (Inbox v2).
//
// Prekey record (stable key):
//   dht_key  = SHA3-256("prekeys" || key_b_pub)
//   value    = {timestamp, prekeys:[pub, ...], signature: ML-DSA-65(Key A, ...)}

namespace sw::dht {

// ── Key derivation helpers ────────────────────────────────────────────────────

// SHA3-256(key_b_pub || timeslot)
Key32 guard_dht_key(const crypto::KemPubKey& key_b_pub, uint64_t timeslot);

// SHAKE-256(key_b_pub || timeslot || "guard_record", 32)
Key32 guard_aead_key(const crypto::KemPubKey& key_b_pub, uint64_t timeslot);

// SHA3-256("prekeys" || key_b_pub)
Key32 prekey_dht_key(const crypto::KemPubKey& key_b_pub);

// ── Guard record ──────────────────────────────────────────────────────────────

struct GuardPlaintext {
    Bytes    guard_node_id;      // SHA3-256(Key H pubkey) of the guard relay, 32 bytes
    std::string guard_endpoint;  // "ip:port"
    SessionToken session_token;
    bool     prekey_available;
    Bytes    inbox_auth_key;     // Key C pubkey (1952 bytes) or empty
    uint64_t inbox_auth_expiry;  // unix seconds
};

// Build version-1 guard record (Client-signed with Key A).
// Returns raw CBOR bytes suitable for DHT publication.
Bytes build_guard_record_v1(
    const crypto::KemPubKey&  key_b_pub,
    uint64_t                  timeslot,
    const GuardPlaintext&     plaintext,
    const crypto::DsaPrivKey& key_a_priv);

// Build version-2 guard record (Inbox-signed with Key C + delegation cert).
// ── Delegation certificate (Key A grants Key C the right to sign DHT records) ─

struct DelegationCert {
    crypto::DsaPubKey key_c_pubkey;
    crypto::DsaPubKey owner_key_a_pubkey;
    uint64_t issued_at;
    uint64_t expires_at;
};

// Build and sign a delegation cert. Sign payload:
//   key_c_pubkey || key_a_pubkey || "inbox" || issued_at_be8 || expires_at_be8
Bytes build_delegation_cert(const DelegationCert& cert,
                             const crypto::DsaPrivKey& key_a_priv);

// Verify delegation cert. Returns the key_c_pubkey if valid.
// Throws std::runtime_error on any failure.
crypto::DsaPubKey verify_delegation_cert(ByteSpan cert_cbor,
                                          const crypto::DsaPubKey& key_a_pub);

Bytes build_guard_record_v2(
    const crypto::KemPubKey&  key_b_pub,
    uint64_t                  timeslot,
    const GuardPlaintext&     plaintext,
    const crypto::DsaPrivKey& key_c_priv,
    ByteSpan                  dht_delegation_cert_cbor);

// Parse and verify a guard record. Returns decrypted plaintext.
// key_b_pub is needed for AEAD key derivation and signature verification.
// key_a_pub is the owner's Key A pubkey (used to verify v1 or the delegation cert in v2).
// Throws std::runtime_error on any verification failure.
GuardPlaintext parse_guard_record(
    ByteSpan                  record_cbor,
    const crypto::KemPubKey&  key_b_pub,
    const crypto::DsaPubKey&  key_a_pub,
    uint64_t                  timeslot);

// ── Prekey record ─────────────────────────────────────────────────────────────

struct PrekeyRecord {
    uint64_t timestamp;
    std::vector<crypto::KemPubKey> prekeys;
};

Bytes build_prekey_record(
    const crypto::KemPubKey&   key_b_pub,
    const PrekeyRecord&        rec,
    const crypto::DsaPrivKey&  key_a_priv);

PrekeyRecord parse_prekey_record(
    ByteSpan                  record_cbor,
    const crypto::KemPubKey&  key_b_pub,
    const crypto::DsaPubKey&  key_a_pub);

} // namespace sw::dht
