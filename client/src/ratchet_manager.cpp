#include "ratchet_manager.hpp"
#include "keystore.hpp"
#include <stdexcept>

namespace sw::client {

using namespace sw::ratchet;
using namespace sw::crypto;

RatchetManager::RatchetManager(Keystore& ks) : ks_(ks) {}

bool RatchetManager::has_state(const std::string& conv_id) const {
    if (cache_.count(conv_id)) return true;
    return ks_.has_ratchet_state(conv_id);
}

KemCt RatchetManager::init_as_sender(
        const std::string& conv_id,
        const KemPubKey& peer_prekey_pub,
        const KemPubKey& my_key_b_pub,
        const KemPubKey& peer_key_b_pub) {
    auto result = ratchet::init_as_sender(peer_prekey_pub, my_key_b_pub, peer_key_b_pub);
    cache_[conv_id] = result.state;
    persist(conv_id, result.state);
    return result.prekey_ct;
}

void RatchetManager::init_as_receiver(
        const std::string& conv_id,
        const KemPrivKey& my_prekey_priv,
        const KemCt&      prekey_ct,
        const KemPubKey&  sender_key_b_pub,
        const KemPubKey&  my_key_b_pub,
        const KemPubKey&  sender_ratchet_pub) {
    State st = ratchet::init_as_receiver(
        my_prekey_priv, prekey_ct,
        sender_key_b_pub, my_key_b_pub, sender_ratchet_pub);
    cache_[conv_id] = st;
    persist(conv_id, st);
}

ratchet::Message RatchetManager::encrypt(const std::string& conv_id,
                                           ByteSpan plaintext) {
    State& st = load(conv_id);
    auto msg = ratchet::encrypt(st, plaintext);
    persist(conv_id, st);
    return msg;
}

Bytes RatchetManager::decrypt(const std::string& conv_id,
                               const ratchet::Message& msg) {
    State& st = load(conv_id);
    Bytes plain = ratchet::decrypt(st, msg);
    persist(conv_id, st);
    return plain;
}

ratchet::State& RatchetManager::load(const std::string& conv_id) {
    auto it = cache_.find(conv_id);
    if (it != cache_.end()) return it->second;

    Bytes data = ks_.get_ratchet_state(conv_id);
    if (data.empty())
        throw std::runtime_error("no ratchet state for conversation: " + conv_id);

    cache_[conv_id] = ratchet::deserialize(ByteSpan{data.data(), data.size()});
    return cache_[conv_id];
}

void RatchetManager::persist(const std::string& conv_id,
                              const ratchet::State& st) {
    Bytes data = ratchet::serialize(st);
    ks_.set_ratchet_state(conv_id, data);
}

} // namespace sw::client
