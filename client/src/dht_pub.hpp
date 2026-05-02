#pragma once
#include <sw/types.hpp>
#include <sw/crypto/mlkem.hpp>
#include <sw/crypto/mldsa.hpp>
#include <string>
#include <vector>

namespace sw::client {

struct GuardInfo {
    std::string guard_node_id;
    std::string guard_endpoint;
    Bytes       session_token; // 32 bytes
    Bytes       outbox_key_c_pubkey;
    int64_t     outbox_auth_expiry;
};

// Build CBOR-encoded DHT guard record for the given Key B and timeslot.
// Returns {dht_key (32B), dht_value (CBOR bytes)}.
std::pair<Key32, Bytes> build_guard_record(
        const crypto::KemPubKey& key_b_kem_pub,
        const crypto::DsaPrivKey& key_a_priv,
        uint64_t timeslot,
        const GuardInfo& guard);

// Build CBOR-encoded DHT prekey record for the given Key B.
// prekeys: list of Key D pubkeys to publish.
std::pair<Key32, Bytes> build_prekey_record(
        const crypto::KemPubKey& key_b_kem_pub,
        const crypto::DsaPrivKey& key_a_priv,
        const std::vector<crypto::KemPubKey>& prekeys,
        int64_t now_s);

} // namespace sw::client
