#include <sw/ratchet/ratchet.hpp>
#include <sw/crypto/kdf.hpp>
#include <cbor.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>

using namespace sw::crypto;

namespace sw::ratchet {

namespace {

// Pack (epoch, msg_num) into a single key for the skipped_keys map.
inline uint64_t skip_key(uint32_t epoch, uint32_t msg_num) {
    return (static_cast<uint64_t>(epoch) << 32) | msg_num;
}

// SHAKE-256(parts..., 32) — convenience using the as_bytes helpers from kdf.hpp.
Key32 kdf(std::initializer_list<ByteSpan> parts) {
    return shake256_32(parts);
}

// Derive message key and advance chain key in place.
Key32 chain_step(Key32& chain_key) {
    Key32 msg_key = kdf({as_bytes(chain_key), as_bytes("message_key")});
    chain_key     = kdf({as_bytes(chain_key), as_bytes("next_chain_key")});
    return msg_key;
}

// Advance recv_chain_key, saving skipped message keys up to target_msg_num.
void advance_recv_chain(State& state, uint32_t epoch, uint32_t target_msg_num) {
    while (state.recv_msg_num < target_msg_num) {
        if (state.skipped_keys.size() >= MAX_SKIPPED_KEYS)
            throw std::runtime_error("Too many skipped messages");
        Key32 mk = chain_step(state.recv_chain_key);
        state.skipped_keys[skip_key(epoch, state.recv_msg_num)] = mk;
        state.recv_msg_num++;
    }
}

// Apply a KEM ratchet step on receive: derive new root_key and recv_chain_key.
void apply_kem_step_recv(State& state, const KemCt& kem_ct,
                          const KemPubKey& sender_pub, uint32_t new_epoch,
                          uint32_t prev_count) {
    // Drain remaining messages from the outgoing epoch (save skip keys).
    advance_recv_chain(state, state.recv_epoch, prev_count);

    KemSS ss = mlkem_decapsulate(state.my_ratchet_kem.priv, kem_ct);

    Key32 new_root = kdf({as_bytes(state.root_key), as_bytes(ss),
                           as_bytes("ratchet_step")});

    // "send_chain" label is from the SENDER's perspective; from our side it's recv.
    state.recv_chain_key = kdf({as_bytes(new_root), as_bytes("send_chain")});
    state.root_key       = new_root;
    state.recv_epoch     = new_epoch;
    state.recv_msg_num   = 0;
    state.peer_ratchet_pub = sender_pub;
    state.need_kem_step  = true;  // we'll need to ratchet forward when we next send
}

} // namespace

// ── Init ─────────────────────────────────────────────────────────────────────

InitResult init_as_sender(const KemPubKey& peer_prekey_pub,
                           const KemPubKey& my_key_b_pub,
                           const KemPubKey& peer_key_b_pub) {
    auto [prekey_ct, prekey_ss] = mlkem_encapsulate(peer_prekey_pub);

    Key32 root_key = kdf({as_bytes(prekey_ss), as_bytes(my_key_b_pub),
                           as_bytes(peer_key_b_pub), as_bytes("ratchet_init")});

    State state{};
    state.root_key       = root_key;
    state.send_chain_key = kdf({as_bytes(root_key), as_bytes("send_chain")});
    state.recv_chain_key = kdf({as_bytes(root_key), as_bytes("recv_chain")});
    state.send_epoch     = 0;
    state.recv_epoch     = 0;
    state.send_msg_num   = 0;
    state.recv_msg_num   = 0;
    state.prev_send_count = 0;
    state.need_kem_step  = false;  // sender starts at epoch 0, no KEM step needed yet
    state.my_ratchet_kem = mlkem_keygen();
    state.peer_ratchet_pub = peer_prekey_pub;  // used for first direction-change KEM step

    return {std::move(state), prekey_ct, state.my_ratchet_kem.pub};
}

State init_as_receiver(const KemPrivKey& my_prekey_priv,
                        const KemCt&     prekey_ct,
                        const KemPubKey& sender_key_b_pub,
                        const KemPubKey& my_key_b_pub,
                        const KemPubKey& sender_ratchet_pub) {
    KemSS prekey_ss = mlkem_decapsulate(my_prekey_priv, prekey_ct);

    Key32 root_key = kdf({as_bytes(prekey_ss), as_bytes(sender_key_b_pub),
                           as_bytes(my_key_b_pub), as_bytes("ratchet_init")});

    State state{};
    state.root_key       = root_key;
    // Receiver: "recv_chain" = the sender's "send_chain", and vice-versa.
    state.recv_chain_key = kdf({as_bytes(root_key), as_bytes("send_chain")});
    state.send_chain_key = kdf({as_bytes(root_key), as_bytes("recv_chain")});
    state.send_epoch     = 0;
    state.recv_epoch     = 0;
    state.send_msg_num   = 0;
    state.recv_msg_num   = 0;
    state.prev_send_count = 0;
    state.need_kem_step  = true;  // receiver must do KEM step before first send
    state.my_ratchet_kem = mlkem_keygen();
    state.peer_ratchet_pub = sender_ratchet_pub;

    return state;
}

// ── Encrypt ──────────────────────────────────────────────────────────────────

Message encrypt(State& state, ByteSpan plaintext) {
    Message msg{};

    // KEM ratchet step if direction changed since last send.
    if (state.need_kem_step) {
        auto [kem_ct, ss] = mlkem_encapsulate(state.peer_ratchet_pub);

        Key32 new_root = kdf({as_bytes(state.root_key), as_bytes(ss),
                               as_bytes("ratchet_step")});

        state.prev_send_count = state.send_msg_num;
        state.send_msg_num    = 0;
        state.send_epoch++;
        state.send_chain_key  = kdf({as_bytes(new_root), as_bytes("send_chain")});
        state.root_key        = new_root;
        state.my_ratchet_kem  = mlkem_keygen();
        state.need_kem_step   = false;

        msg.header.kem_ct = kem_ct;
    }

    msg.header.epoch              = state.send_epoch;
    msg.header.msg_num            = state.send_msg_num;
    msg.header.prev_count         = state.prev_send_count;
    msg.header.sender_ratchet_pub = state.my_ratchet_kem.pub;

    AesKey msg_key_arr;
    Key32 mk = chain_step(state.send_chain_key);
    std::copy(mk.begin(), mk.end(), msg_key_arr.begin());
    state.send_msg_num++;

    AesEncrypted enc = aes_encrypt(msg_key_arr, plaintext);
    msg.nonce      = enc.nonce;
    msg.ciphertext = std::move(enc.ciphertext);
    msg.tag        = enc.tag;

    return msg;
}

// ── Decrypt ──────────────────────────────────────────────────────────────────

Bytes decrypt(State& state, const Message& msg) {
    const auto& hdr = msg.header;

    // Check if this message is from a cached skipped-key slot.
    auto sk_it = state.skipped_keys.find(skip_key(hdr.epoch, hdr.msg_num));
    if (sk_it != state.skipped_keys.end()) {
        AesKey msg_key_arr;
        std::copy(sk_it->second.begin(), sk_it->second.end(), msg_key_arr.begin());
        state.skipped_keys.erase(sk_it);
        return aes_decrypt(msg_key_arr, msg.nonce, msg.ciphertext, msg.tag);
    }

    // New epoch from sender — do KEM ratchet step.
    if (hdr.epoch > state.recv_epoch) {
        if (!hdr.kem_ct)
            throw std::runtime_error("Missing kem_ct for new ratchet epoch");
        apply_kem_step_recv(state, *hdr.kem_ct, hdr.sender_ratchet_pub,
                             hdr.epoch, hdr.prev_count);
    }

    if (hdr.epoch < state.recv_epoch)
        throw std::runtime_error("Message from past epoch without skipped key");

    // Advance recv chain, saving skipped keys for any gaps.
    advance_recv_chain(state, hdr.epoch, hdr.msg_num);

    AesKey msg_key_arr;
    Key32 mk = chain_step(state.recv_chain_key);
    std::copy(mk.begin(), mk.end(), msg_key_arr.begin());
    state.recv_msg_num++;

    return aes_decrypt(msg_key_arr, msg.nonce, msg.ciphertext, msg.tag);
}

// ── Serialization (CBOR) ─────────────────────────────────────────────────────
// Format: definite map with string keys, all binary fields as bstr.

Bytes serialize(const State& state) {
    // Count skipped keys to size the map.
    size_t skip_count = state.skipped_keys.size();

    // We encode skipped_keys as an array of [packed_uint64, key32_bstr] pairs.
    cbor_item_t* root = cbor_new_definite_map(12);

    auto add_bstr = [&](const char* key, const uint8_t* data, size_t len) {
        cbor_item_t* k = cbor_build_string(key);
        cbor_item_t* v = cbor_build_bytestring(data, len);
        cbor_map_add(root, {k, v});
        cbor_decref(&k);
        cbor_decref(&v);
    };
    auto add_uint = [&](const char* key, uint64_t val) {
        cbor_item_t* k = cbor_build_string(key);
        cbor_item_t* v = cbor_build_uint64(val);
        cbor_map_add(root, {k, v});
        cbor_decref(&k);
        cbor_decref(&v);
    };
    auto add_bool = [&](const char* key, bool val) {
        cbor_item_t* k = cbor_build_string(key);
        cbor_item_t* v = cbor_build_bool(val);
        cbor_map_add(root, {k, v});
        cbor_decref(&k);
        cbor_decref(&v);
    };

    add_bstr("root_key",        state.root_key.data(),                    32);
    add_bstr("send_chain",      state.send_chain_key.data(),              32);
    add_bstr("recv_chain",      state.recv_chain_key.data(),              32);
    add_uint("send_epoch",      state.send_epoch);
    add_uint("recv_epoch",      state.recv_epoch);
    add_uint("send_msg_num",    state.send_msg_num);
    add_uint("recv_msg_num",    state.recv_msg_num);
    add_uint("prev_send_count", state.prev_send_count);
    add_bool("need_kem_step",   state.need_kem_step);
    add_bstr("my_ratchet_pub",  state.my_ratchet_kem.pub.data(),  MLKEM768_PUBKEY_BYTES);
    add_bstr("my_ratchet_priv", state.my_ratchet_kem.priv.data(), MLKEM768_PRIVKEY_BYTES);
    add_bstr("peer_ratchet_pub",state.peer_ratchet_pub.data(),     MLKEM768_PUBKEY_BYTES);

    // Encode skipped_keys as array of [uint64, bstr] pairs.
    cbor_item_t* sk_arr = cbor_new_definite_array(skip_count);
    for (auto& [packed, mk] : state.skipped_keys) {
        cbor_item_t* pair = cbor_new_definite_array(2);
        cbor_item_t* pk   = cbor_build_uint64(packed);
        cbor_item_t* mv   = cbor_build_bytestring(mk.data(), 32);
        cbor_array_push(pair, pk);
        cbor_array_push(pair, mv);
        cbor_decref(&pk);
        cbor_decref(&mv);
        cbor_array_push(sk_arr, pair);
        cbor_decref(&pair);
    }
    cbor_item_t* sk_key = cbor_build_string("skipped_keys");
    cbor_map_add(root, {sk_key, sk_arr});
    cbor_decref(&sk_key);
    cbor_decref(&sk_arr);

    unsigned char* buf = nullptr;
    size_t buf_size    = 0;
    size_t written     = cbor_serialize_alloc(root, &buf, &buf_size);
    cbor_decref(&root);

    Bytes out(buf, buf + written);
    free(buf);
    return out;
}

State deserialize(ByteSpan data) {
    struct cbor_load_result res{};
    cbor_item_t* root = cbor_load(data.data(), data.size(), &res);
    if (!root || res.error.code != CBOR_ERR_NONE)
        throw std::runtime_error("ratchet::deserialize: CBOR parse error");

    if (!cbor_isa_map(root))
        throw std::runtime_error("ratchet::deserialize: expected map");

    State state{};
    size_t n = cbor_map_size(root);
    auto pairs = cbor_map_handle(root);

    auto get_bstr = [&](const char* key, uint8_t* dst, size_t expected) {
        for (size_t i = 0; i < n; ++i) {
            if (!cbor_isa_string(pairs[i].key)) continue;
            auto klen = cbor_string_length(pairs[i].key);
            auto kptr = cbor_string_handle(pairs[i].key);
            if (std::string_view{reinterpret_cast<const char*>(kptr), klen} != key) continue;
            if (!cbor_isa_bytestring(pairs[i].value))
                throw std::runtime_error(std::string("expected bstr for ") + key);
            size_t vlen = cbor_bytestring_length(pairs[i].value);
            if (vlen != expected)
                throw std::runtime_error(std::string("wrong size for ") + key);
            std::memcpy(dst, cbor_bytestring_handle(pairs[i].value), vlen);
            return;
        }
        throw std::runtime_error(std::string("missing key: ") + key);
    };
    auto get_uint = [&](const char* key) -> uint64_t {
        for (size_t i = 0; i < n; ++i) {
            if (!cbor_isa_string(pairs[i].key)) continue;
            auto klen = cbor_string_length(pairs[i].key);
            auto kptr = cbor_string_handle(pairs[i].key);
            if (std::string_view{reinterpret_cast<const char*>(kptr), klen} != key) continue;
            return cbor_get_uint64(pairs[i].value);
        }
        throw std::runtime_error(std::string("missing key: ") + key);
    };
    auto get_bool = [&](const char* key) -> bool {
        for (size_t i = 0; i < n; ++i) {
            if (!cbor_isa_string(pairs[i].key)) continue;
            auto klen = cbor_string_length(pairs[i].key);
            auto kptr = cbor_string_handle(pairs[i].key);
            if (std::string_view{reinterpret_cast<const char*>(kptr), klen} != key) continue;
            return cbor_is_bool(pairs[i].value) && cbor_get_bool(pairs[i].value);
        }
        throw std::runtime_error(std::string("missing key: ") + key);
    };

    get_bstr("root_key",        state.root_key.data(),                    32);
    get_bstr("send_chain",      state.send_chain_key.data(),              32);
    get_bstr("recv_chain",      state.recv_chain_key.data(),              32);
    state.send_epoch     = static_cast<uint32_t>(get_uint("send_epoch"));
    state.recv_epoch     = static_cast<uint32_t>(get_uint("recv_epoch"));
    state.send_msg_num   = static_cast<uint32_t>(get_uint("send_msg_num"));
    state.recv_msg_num   = static_cast<uint32_t>(get_uint("recv_msg_num"));
    state.prev_send_count= static_cast<uint32_t>(get_uint("prev_send_count"));
    state.need_kem_step  = get_bool("need_kem_step");
    get_bstr("my_ratchet_pub",  state.my_ratchet_kem.pub.data(),  MLKEM768_PUBKEY_BYTES);
    get_bstr("my_ratchet_priv", state.my_ratchet_kem.priv.data(), MLKEM768_PRIVKEY_BYTES);
    get_bstr("peer_ratchet_pub",state.peer_ratchet_pub.data(),     MLKEM768_PUBKEY_BYTES);

    // Decode skipped_keys.
    for (size_t i = 0; i < n; ++i) {
        if (!cbor_isa_string(pairs[i].key)) continue;
        auto klen = cbor_string_length(pairs[i].key);
        auto kptr = cbor_string_handle(pairs[i].key);
        if (std::string_view{reinterpret_cast<const char*>(kptr), klen} != "skipped_keys") continue;

        cbor_item_t* arr = pairs[i].value;
        if (!cbor_isa_array(arr)) break;
        size_t arr_len = cbor_array_size(arr);
        auto arr_items = cbor_array_handle(arr);
        for (size_t j = 0; j < arr_len; ++j) {
            cbor_item_t* pair = arr_items[j];
            if (!cbor_isa_array(pair) || cbor_array_size(pair) < 2) continue;
            auto pe = cbor_array_handle(pair);
            uint64_t packed = cbor_get_uint64(pe[0]);
            if (cbor_bytestring_length(pe[1]) != 32) continue;
            Key32 mk;
            std::memcpy(mk.data(), cbor_bytestring_handle(pe[1]), 32);
            state.skipped_keys[packed] = mk;
        }
        break;
    }

    cbor_decref(&root);
    return state;
}

} // namespace sw::ratchet
