#include "dht_pub.hpp"
#include <sw/crypto/kdf.hpp>
#include <sw/crypto/aes_gcm.hpp>
#include <cbor.h>
#include <sodium.h>
#include <stdexcept>
#include <cstring>
#include <ctime>

namespace sw::client {

using namespace sw::crypto;

static Bytes cbor_ser(cbor_item_t* item) {
    unsigned char* buf = nullptr;
    size_t buf_size = 0;
    size_t n = cbor_serialize_alloc(item, &buf, &buf_size);
    Bytes result(buf, buf + n);
    free(buf);
    return result;
}

static void map_add_bytes(cbor_item_t* m, const char* k,
                           const uint8_t* d, size_t l) {
    cbor_map_add(m, (struct cbor_pair){
        .key   = cbor_move(cbor_build_string(k)),
        .value = cbor_move(cbor_build_bytestring(d, l))
    });
}
static void map_add_str(cbor_item_t* m, const char* k, const char* v) {
    cbor_map_add(m, (struct cbor_pair){
        .key   = cbor_move(cbor_build_string(k)),
        .value = cbor_move(cbor_build_string(v))
    });
}
static void map_add_uint(cbor_item_t* m, const char* k, uint64_t v) {
    cbor_map_add(m, (struct cbor_pair){
        .key   = cbor_move(cbor_build_string(k)),
        .value = cbor_move(cbor_build_uint64(v))
    });
}
static void map_add_bool(cbor_item_t* m, const char* k, bool v) {
    cbor_map_add(m, (struct cbor_pair){
        .key   = cbor_move(cbor_build_string(k)),
        .value = cbor_move(v ? cbor_new_true() : cbor_new_false())
    });
}

std::pair<Key32, Bytes> build_guard_record(
        const KemPubKey&  key_b_kem_pub,
        const DsaPrivKey& key_a_priv,
        uint64_t          timeslot,
        const GuardInfo&  guard) {
    // dht_key = SHA3-256(key_b_kem_pub || timeslot_bytes)
    const uint64_t orig_timeslot = timeslot;
    uint8_t ts_bytes[8];
    for (int i = 7; i >= 0; --i) {
        ts_bytes[i] = timeslot & 0xff;
        timeslot >>= 8;
    }
    Key32 dht_key = sha3_256({
        ByteSpan{key_b_kem_pub.data(), key_b_kem_pub.size()},
        ByteSpan{ts_bytes, 8}
    });

    // aead_key = SHAKE-256(key_b_kem_pub || timeslot || "guard_record", output=32)
    Key32 aead_key = shake256_32({
        ByteSpan{key_b_kem_pub.data(), key_b_kem_pub.size()},
        ByteSpan{ts_bytes, 8},
        as_bytes("guard_record")
    });

    // Build plaintext CBOR map
    cbor_item_t* plain_map = cbor_new_definite_map(6);
    map_add_str(plain_map,  "guard_node_id",   guard.guard_node_id.c_str());
    map_add_str(plain_map,  "guard_endpoint",  guard.guard_endpoint.c_str());
    map_add_bytes(plain_map,"session_token",   guard.session_token.data(),
                                               guard.session_token.size());
    map_add_bool(plain_map, "prekey_available",!guard.outbox_key_c_pubkey.empty());
    map_add_bytes(plain_map,"inbox_auth_key",  guard.outbox_key_c_pubkey.data(),
                                               guard.outbox_key_c_pubkey.size());
    map_add_uint(plain_map, "inbox_auth_expiry",
                 static_cast<uint64_t>(guard.outbox_auth_expiry));
    Bytes plain_bytes = cbor_ser(plain_map);
    cbor_decref(&plain_map);

    AesKey akey;
    std::copy(aead_key.begin(), aead_key.end(), akey.begin());
    AesEncrypted enc = aes_encrypt(akey,
                                   ByteSpan{plain_bytes.data(), plain_bytes.size()});

    // Build outer CBOR: {timeslot, timestamp, ciphertext:{iv,ciphertext,tag}, signature}
    int64_t now_s = static_cast<int64_t>(std::time(nullptr));

    cbor_item_t* ct_map = cbor_new_definite_map(3);
    map_add_bytes(ct_map, "iv",         enc.nonce.data(),     12);
    map_add_bytes(ct_map, "ciphertext", enc.ciphertext.data(),enc.ciphertext.size());
    map_add_bytes(ct_map, "tag",        enc.tag.data(),       16);
    Bytes ct_bytes = cbor_ser(ct_map);
    cbor_decref(&ct_map);

    // Sign: timeslot(8B) || timestamp(8B) || iv(12B) || ciphertext || tag(16B)
    Bytes to_sign;
    to_sign.insert(to_sign.end(), ts_bytes, ts_bytes + 8);
    uint8_t ts_now[8];
    uint64_t now_u = static_cast<uint64_t>(now_s);
    for (int i = 7; i >= 0; --i) { ts_now[i] = now_u & 0xff; now_u >>= 8; }
    to_sign.insert(to_sign.end(), ts_now, ts_now + 8);
    to_sign.insert(to_sign.end(), enc.nonce.begin(), enc.nonce.end());
    to_sign.insert(to_sign.end(), enc.ciphertext.begin(), enc.ciphertext.end());
    to_sign.insert(to_sign.end(), enc.tag.begin(), enc.tag.end());

    DsaSig sig = mldsa_sign(key_a_priv,
                             ByteSpan{to_sign.data(), to_sign.size()});

    cbor_item_t* outer = cbor_new_definite_map(4);
    map_add_uint(outer, "timeslot",  orig_timeslot);
    map_add_uint(outer, "timestamp", static_cast<uint64_t>(now_s));

    cbor_map_add(outer, (struct cbor_pair){
        .key   = cbor_move(cbor_build_string("ciphertext")),
        .value = cbor_move(cbor_load(ct_bytes.data(), ct_bytes.size(), nullptr))
    });
    map_add_bytes(outer, "signature", sig.data(), sig.size());

    Bytes dht_value = cbor_ser(outer);
    cbor_decref(&outer);

    return {dht_key, dht_value};
}

std::pair<Key32, Bytes> build_prekey_record(
        const KemPubKey&                     key_b_kem_pub,
        const DsaPrivKey&                    key_a_priv,
        const std::vector<KemPubKey>&        prekeys,
        int64_t                              now_s) {
    // prekey_dht_key = SHA3-256("prekeys" || key_b_kem_pub)
    Key32 dht_key = sha3_256({
        as_bytes("prekeys"),
        ByteSpan{key_b_kem_pub.data(), key_b_kem_pub.size()}
    });

    // Build prekeys CBOR array
    cbor_item_t* arr = cbor_new_definite_array(prekeys.size());
    for (const auto& pk : prekeys)
        cbor_array_push(arr, cbor_move(cbor_build_bytestring(pk.data(), pk.size())));
    Bytes prekeys_cbor = cbor_ser(arr);
    cbor_decref(&arr);

    // Sign: timestamp(8B) || prekeys_cbor
    Bytes to_sign;
    uint64_t ts = static_cast<uint64_t>(now_s);
    for (int i = 7; i >= 0; --i) { to_sign.push_back((ts >> (i * 8)) & 0xff); }
    to_sign.insert(to_sign.end(), prekeys_cbor.begin(), prekeys_cbor.end());

    DsaSig sig = mldsa_sign(key_a_priv,
                             ByteSpan{to_sign.data(), to_sign.size()});

    cbor_item_t* root = cbor_new_definite_map(3);
    map_add_uint(root, "timestamp", static_cast<uint64_t>(now_s));
    cbor_map_add(root, (struct cbor_pair){
        .key   = cbor_move(cbor_build_string("prekeys")),
        .value = cbor_move(cbor_load(prekeys_cbor.data(), prekeys_cbor.size(), nullptr))
    });
    map_add_bytes(root, "signature", sig.data(), sig.size());

    Bytes dht_value = cbor_ser(root);
    cbor_decref(&root);

    return {dht_key, dht_value};
}

} // namespace sw::client
