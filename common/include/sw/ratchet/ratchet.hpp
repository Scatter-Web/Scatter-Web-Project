#pragma once
#include <sw/types.hpp>
#include <sw/crypto/mlkem.hpp>
#include <sw/crypto/aes_gcm.hpp>
#include <optional>
#include <unordered_map>

// Double Ratchet with ML-KEM-768 (post-quantum Signal-style ratchet).
//
// KEM ratchet: triggers when receiver first sends a reply (direction change),
// analogous to Signal's DH ratchet step. Each new send direction encapsulates
// to the peer's current KEM pubkey and derives fresh send/recv chains.
//
// Symmetric ratchet: advances per message within a KEM epoch, enabling
// out-of-order delivery of up to MAX_SKIPPED_KEYS skipped messages.

namespace sw::ratchet {

constexpr uint32_t MAX_SKIPPED_KEYS = 100;

struct State {
    Key32 root_key;
    Key32 send_chain_key;
    Key32 recv_chain_key;

    uint32_t send_epoch    = 0;  // KEM ratchet step counter (send direction)
    uint32_t recv_epoch    = 0;  // KEM ratchet step counter (recv direction)
    uint32_t send_msg_num  = 0;  // symmetric counter for current send epoch
    uint32_t recv_msg_num  = 0;  // symmetric counter for current recv epoch
    uint32_t prev_send_count = 0; // # msgs sent in previous send epoch
    bool need_kem_step     = false; // true when a KEM ratchet step is pending before next send

    // My current ratchet KEM keypair (new one generated on each KEM ratchet step)
    crypto::KemKeyPair my_ratchet_kem;
    // Peer's current ratchet public key
    crypto::KemPubKey peer_ratchet_pub;

    // Cached message keys for out-of-order messages: (epoch, msg_num) → msg_key
    // We use a flat map keyed by a packed uint64: (epoch << 32 | msg_num)
    std::unordered_map<uint64_t, Key32> skipped_keys;
};

// Wire header included in every ratchet-encrypted envelope.
struct Header {
    uint32_t epoch;         // KEM ratchet step counter (incremented on direction change)
    uint32_t msg_num;       // symmetric message number within epoch
    uint32_t prev_count;    // # msgs sender sent in previous epoch (for skip key recovery)
    crypto::KemPubKey sender_ratchet_pub; // sender's current ratchet pub
    // kem_ct: only present when epoch increased (direction change)
    std::optional<crypto::KemCt> kem_ct;
};

struct Message {
    Header header;
    crypto::AesNonce nonce;
    Bytes ciphertext;
    crypto::AesTag tag;
};

// Initialize as the session initiator.
// A calls this using B's prekey (Key D) and both parties' Key B pubkeys.
// Returns the initial state for A plus the KEM ciphertext A must send to B.
struct InitResult {
    State state;
    crypto::KemCt prekey_ct;   // A sends this to B so B can derive root_key
    crypto::KemPubKey my_ratchet_pub; // A sends this as first epoch sender_ratchet_pub
};
InitResult init_as_sender(const crypto::KemPubKey& peer_prekey_pub,
                          const crypto::KemPubKey& my_key_b_pub,
                          const crypto::KemPubKey& peer_key_b_pub);

// Initialize as the session receiver.
// B calls this after receiving A's contact_request containing prekey_ct and
// A's initial ratchet pubkey.
State init_as_receiver(const crypto::KemPrivKey& my_prekey_priv,
                       const crypto::KemCt& prekey_ct,
                       const crypto::KemPubKey& sender_key_b_pub,
                       const crypto::KemPubKey& my_key_b_pub,
                       const crypto::KemPubKey& sender_ratchet_pub);

// Encrypt plaintext, advancing the ratchet state. May trigger a KEM ratchet
// step if this is the first message sent after receiving from the peer.
Message encrypt(State& state, ByteSpan plaintext);

// Decrypt a received message, advancing the ratchet state.
// Throws std::runtime_error on authentication failure or too many skipped messages.
Bytes decrypt(State& state, const Message& msg);

// CBOR serialization for keystore storage.
Bytes serialize(const State& state);
State deserialize(ByteSpan data);

} // namespace sw::ratchet
