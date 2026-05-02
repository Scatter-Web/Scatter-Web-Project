#pragma once
#include <sw/ratchet/ratchet.hpp>
#include <sw/crypto/mlkem.hpp>
#include <sw/types.hpp>
#include <string>
#include <unordered_map>

namespace sw::client {

class Keystore;

// Manages one ratchet state per DM conversation.
// States are loaded lazily from the keystore and written back on every step.
class RatchetManager {
public:
    explicit RatchetManager(Keystore& ks);

    bool has_state(const std::string& conv_id) const;

    // Init as the party sending the first message (contact request sender).
    // Returns the KEM ciphertext that must be sent to the peer so they can
    // derive the same root key.
    crypto::KemCt init_as_sender(const std::string& conv_id,
                                  const crypto::KemPubKey& peer_prekey_pub,
                                  const crypto::KemPubKey& my_key_b_pub,
                                  const crypto::KemPubKey& peer_key_b_pub);

    // Init as the party receiving the first message.
    void init_as_receiver(const std::string& conv_id,
                           const crypto::KemPrivKey& my_prekey_priv,
                           const crypto::KemCt&      prekey_ct,
                           const crypto::KemPubKey&  sender_key_b_pub,
                           const crypto::KemPubKey&  my_key_b_pub,
                           const crypto::KemPubKey&  sender_ratchet_pub);

    // Encrypt plaintext; advances state and persists to keystore.
    ratchet::Message encrypt(const std::string& conv_id, ByteSpan plaintext);

    // Decrypt message; advances state and persists to keystore.
    Bytes decrypt(const std::string& conv_id, const ratchet::Message& msg);

private:
    Keystore&                                     ks_;
    std::unordered_map<std::string, ratchet::State> cache_;

    ratchet::State& load(const std::string& conv_id);
    void            persist(const std::string& conv_id, const ratchet::State& st);
};

} // namespace sw::client
