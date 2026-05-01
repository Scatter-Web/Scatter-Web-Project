#include <sw/dht/record.hpp>
#include <sw/crypto/kdf.hpp>
#include <sw/crypto/aes_gcm.hpp>
#include <cbor.h>
#include <cstring>
#include <ctime>
#include <stdexcept>

using namespace sw::crypto;

namespace sw::dht {

// ── Key derivation ────────────────────────────────────────────────────────────

Key32 guard_dht_key(const KemPubKey& key_b_pub, uint64_t timeslot) {
    uint8_t ts_be[8];
    for (int i = 7; i >= 0; --i) { ts_be[i] = timeslot & 0xFF; timeslot >>= 8; }
    return sha3_256({as_bytes(key_b_pub), ByteSpan{ts_be, 8}});
}

Key32 guard_aead_key(const KemPubKey& key_b_pub, uint64_t timeslot) {
    uint8_t ts_be[8];
    uint64_t t = timeslot;
    for (int i = 7; i >= 0; --i) { ts_be[i] = t & 0xFF; t >>= 8; }
    return shake256_32({as_bytes(key_b_pub), ByteSpan{ts_be, 8},
                         as_bytes("guard_record")});
}

Key32 prekey_dht_key(const KemPubKey& key_b_pub) {
    return sha3_256({as_bytes("prekeys"), as_bytes(key_b_pub)});
}

// ── CBOR helpers ──────────────────────────────────────────────────────────────

namespace {

Bytes serialize_item(cbor_item_t* item) {
    unsigned char* buf = nullptr;
    size_t buf_size    = 0;
    size_t written     = cbor_serialize_alloc(item, &buf, &buf_size);
    Bytes out(buf, buf + written);
    free(buf);
    return out;
}

void map_add_bstr(cbor_item_t* map, const char* key, const uint8_t* data, size_t len) {
    cbor_item_t* k = cbor_build_string(key);
    cbor_item_t* v = cbor_build_bytestring(data, len);
    cbor_map_add(map, {k, v});
    cbor_decref(&k); cbor_decref(&v);
}

void map_add_uint(cbor_item_t* map, const char* key, uint64_t val) {
    cbor_item_t* k = cbor_build_string(key);
    cbor_item_t* v = cbor_build_uint64(val);
    cbor_map_add(map, {k, v});
    cbor_decref(&k); cbor_decref(&v);
}

void map_add_bool(cbor_item_t* map, const char* key, bool val) {
    cbor_item_t* k = cbor_build_string(key);
    cbor_item_t* v = cbor_build_bool(val);
    cbor_map_add(map, {k, v});
    cbor_decref(&k); cbor_decref(&v);
}

void map_add_str(cbor_item_t* map, const char* key, const std::string& val) {
    cbor_item_t* k = cbor_build_string(key);
    cbor_item_t* v = cbor_build_string(val.c_str());
    cbor_map_add(map, {k, v});
    cbor_decref(&k); cbor_decref(&v);
}

void map_add_item(cbor_item_t* map, const char* key, cbor_item_t* val) {
    cbor_item_t* k = cbor_build_string(key);
    cbor_map_add(map, {k, val});
    cbor_decref(&k); cbor_decref(&val);
}

struct CborMap {
    cbor_item_t* root;
    size_t n;
    struct cbor_pair* pairs;
};

CborMap load_map(ByteSpan data) {
    struct cbor_load_result res{};
    cbor_item_t* root = cbor_load(data.data(), data.size(), &res);
    if (!root || res.error.code != CBOR_ERR_NONE)
        throw std::runtime_error("CBOR parse error");
    if (!cbor_isa_map(root)) {
        cbor_decref(&root);
        throw std::runtime_error("Expected top-level map");
    }
    return {root, cbor_map_size(root), cbor_map_handle(root)};
}

cbor_item_t* find_key(const CborMap& m, const char* key) {
    std::string_view sv{key};
    for (size_t i = 0; i < m.n; ++i) {
        if (!cbor_isa_string(m.pairs[i].key)) continue;
        auto klen = cbor_string_length(m.pairs[i].key);
        auto kptr = cbor_string_handle(m.pairs[i].key);
        if (std::string_view{reinterpret_cast<const char*>(kptr), klen} == sv)
            return m.pairs[i].value;
    }
    return nullptr;
}

Bytes bstr_or_throw(cbor_item_t* item, const char* field) {
    if (!item || !cbor_isa_bytestring(item))
        throw std::runtime_error(std::string("Missing/invalid bstr: ") + field);
    return Bytes(cbor_bytestring_handle(item),
                 cbor_bytestring_handle(item) + cbor_bytestring_length(item));
}

// Build the bytes that are signed: timeslot_be8 || timestamp_be8 || iv || ct || tag
Bytes sign_payload_v1(uint64_t timeslot, uint64_t timestamp,
                       const AesNonce& iv, const Bytes& ct, const AesTag& tag) {
    Bytes out;
    out.reserve(8 + 8 + 12 + ct.size() + 16);
    for (int i = 7; i >= 0; --i) out.push_back((timeslot  >> (i*8)) & 0xFF);
    for (int i = 7; i >= 0; --i) out.push_back((timestamp >> (i*8)) & 0xFF);
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

// Same but with target_key_b_pubkey prepended (v2)
Bytes sign_payload_v2(uint64_t timeslot, uint64_t timestamp,
                       const KemPubKey& key_b_pub,
                       const AesNonce& iv, const Bytes& ct, const AesTag& tag) {
    Bytes out;
    out.reserve(8 + 8 + MLKEM768_PUBKEY_BYTES + 12 + ct.size() + 16);
    for (int i = 7; i >= 0; --i) out.push_back((timeslot  >> (i*8)) & 0xFF);
    for (int i = 7; i >= 0; --i) out.push_back((timestamp >> (i*8)) & 0xFF);
    out.insert(out.end(), key_b_pub.begin(), key_b_pub.end());
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

Bytes encode_plaintext(const GuardPlaintext& p) {
    cbor_item_t* m = cbor_new_definite_map(6);
    map_add_bstr(m, "guard_node_id", p.guard_node_id.data(), p.guard_node_id.size());
    map_add_str(m, "guard_endpoint", p.guard_endpoint);
    map_add_bstr(m, "session_token", p.session_token.data(), 32);
    map_add_bool(m, "prekey_available", p.prekey_available);
    map_add_bstr(m, "inbox_auth_key", p.inbox_auth_key.data(), p.inbox_auth_key.size());
    map_add_uint(m, "inbox_auth_expiry", p.inbox_auth_expiry);
    Bytes out = serialize_item(m);
    cbor_decref(&m);
    return out;
}

GuardPlaintext decode_plaintext(ByteSpan data) {
    auto m = load_map(data);
    GuardPlaintext p;

    auto gni = find_key(m, "guard_node_id");
    p.guard_node_id = bstr_or_throw(gni, "guard_node_id");

    auto gep = find_key(m, "guard_endpoint");
    if (!gep || !cbor_isa_string(gep))
        throw std::runtime_error("Missing guard_endpoint");
    p.guard_endpoint = std::string(
        reinterpret_cast<const char*>(cbor_string_handle(gep)), cbor_string_length(gep));

    auto st = find_key(m, "session_token");
    Bytes st_bytes = bstr_or_throw(st, "session_token");
    if (st_bytes.size() != 32) throw std::runtime_error("session_token must be 32 bytes");
    std::copy(st_bytes.begin(), st_bytes.end(), p.session_token.begin());

    auto pa = find_key(m, "prekey_available");
    p.prekey_available = pa && cbor_is_bool(pa) && cbor_get_bool(pa);

    auto iak = find_key(m, "inbox_auth_key");
    if (iak && cbor_isa_bytestring(iak))
        p.inbox_auth_key = bstr_or_throw(iak, "inbox_auth_key");

    auto iae = find_key(m, "inbox_auth_expiry");
    if (iae && cbor_isa_uint(iae))
        p.inbox_auth_expiry = cbor_get_uint64(iae);

    cbor_decref(&m.root);
    return p;
}

} // namespace

// ── Delegation cert ───────────────────────────────────────────────────────────

namespace {

Bytes delegation_sign_payload(const DsaPubKey& key_c_pub,
                               const DsaPubKey& key_a_pub,
                               uint64_t issued_at, uint64_t expires_at) {
    Bytes out;
    out.reserve(MLDSA65_PUBKEY_BYTES * 2 + 5 + 8 + 8);
    out.insert(out.end(), key_c_pub.begin(), key_c_pub.end());
    out.insert(out.end(), key_a_pub.begin(), key_a_pub.end());
    const char scope[] = "inbox";
    out.insert(out.end(), scope, scope + 5);
    for (int i = 7; i >= 0; --i) out.push_back((issued_at  >> (i*8)) & 0xFF);
    for (int i = 7; i >= 0; --i) out.push_back((expires_at >> (i*8)) & 0xFF);
    return out;
}

} // anonymous namespace (delegation helpers)

Bytes build_delegation_cert(const DelegationCert& cert,
                             const DsaPrivKey& key_a_priv) {
    Bytes payload = delegation_sign_payload(cert.key_c_pubkey, cert.owner_key_a_pubkey,
                                             cert.issued_at, cert.expires_at);
    DsaSig sig = mldsa_sign(key_a_priv, payload);

    cbor_item_t* root = cbor_new_definite_map(6);
    map_add_bstr(root, "key_c_pubkey",       cert.key_c_pubkey.data(),       MLDSA65_PUBKEY_BYTES);
    map_add_bstr(root, "owner_key_a_pubkey", cert.owner_key_a_pubkey.data(), MLDSA65_PUBKEY_BYTES);
    map_add_str(root,  "scope",              "inbox");
    map_add_uint(root, "issued_at",          cert.issued_at);
    map_add_uint(root, "expires_at",         cert.expires_at);
    map_add_bstr(root, "signature",          sig.data(), MLDSA65_SIG_BYTES);

    Bytes out = serialize_item(root);
    cbor_decref(&root);
    return out;
}

DsaPubKey verify_delegation_cert(ByteSpan cert_cbor, const DsaPubKey& key_a_pub) {
    auto m = load_map(cert_cbor);

    auto kc_item = find_key(m, "key_c_pubkey");
    Bytes kc_bytes = bstr_or_throw(kc_item, "key_c_pubkey");
    if (kc_bytes.size() != MLDSA65_PUBKEY_BYTES) {
        cbor_decref(&m.root);
        throw std::runtime_error("Bad key_c_pubkey size");
    }
    DsaPubKey key_c_pub;
    std::copy(kc_bytes.begin(), kc_bytes.end(), key_c_pub.begin());

    auto ka_item = find_key(m, "owner_key_a_pubkey");
    Bytes ka_bytes = bstr_or_throw(ka_item, "owner_key_a_pubkey");
    if (ka_bytes.size() != MLDSA65_PUBKEY_BYTES) {
        cbor_decref(&m.root);
        throw std::runtime_error("Bad owner_key_a_pubkey size");
    }

    auto scope_item = find_key(m, "scope");
    if (!scope_item || !cbor_isa_string(scope_item)) {
        cbor_decref(&m.root);
        throw std::runtime_error("Missing scope");
    }
    std::string scope(reinterpret_cast<const char*>(cbor_string_handle(scope_item)),
                      cbor_string_length(scope_item));
    if (scope != "inbox") {
        cbor_decref(&m.root);
        throw std::runtime_error("Delegation cert scope must be 'inbox'");
    }

    auto ia_item = find_key(m, "issued_at");
    auto ea_item = find_key(m, "expires_at");
    if (!ia_item || !ea_item) {
        cbor_decref(&m.root);
        throw std::runtime_error("Missing issued_at/expires_at");
    }
    uint64_t issued_at  = cbor_get_uint64(ia_item);
    uint64_t expires_at = cbor_get_uint64(ea_item);

    auto sig_item = find_key(m, "signature");
    Bytes sig_bytes = bstr_or_throw(sig_item, "signature");
    if (sig_bytes.size() != MLDSA65_SIG_BYTES) {
        cbor_decref(&m.root);
        throw std::runtime_error("Bad delegation cert signature size");
    }
    DsaSig sig;
    std::copy(sig_bytes.begin(), sig_bytes.end(), sig.begin());

    Bytes payload = delegation_sign_payload(key_c_pub, key_a_pub, issued_at, expires_at);
    if (!mldsa_verify(key_a_pub, payload, sig)) {
        cbor_decref(&m.root);
        throw std::runtime_error("Delegation cert signature invalid");
    }

    // Check expiry.
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    if (now > expires_at) {
        cbor_decref(&m.root);
        throw std::runtime_error("Delegation cert expired");
    }

    cbor_decref(&m.root);
    return key_c_pub;
}

// ── Guard record: build ───────────────────────────────────────────────────────

Bytes build_guard_record_v1(const KemPubKey& key_b_pub, uint64_t timeslot,
                              const GuardPlaintext& plaintext,
                              const DsaPrivKey& key_a_priv) {
    uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr));

    AesKey aead_key_arr;
    Key32 ak = guard_aead_key(key_b_pub, timeslot);
    std::copy(ak.begin(), ak.end(), aead_key_arr.begin());

    Bytes pt_cbor = encode_plaintext(plaintext);
    AesEncrypted enc = aes_encrypt(aead_key_arr, pt_cbor);

    Bytes to_sign = sign_payload_v1(timeslot, timestamp, enc.nonce, enc.ciphertext, enc.tag);
    DsaSig sig    = mldsa_sign(key_a_priv, to_sign);

    // Assemble outer record.
    cbor_item_t* ct_map = cbor_new_definite_map(3);
    map_add_bstr(ct_map, "iv",         enc.nonce.data(), 12);
    map_add_bstr(ct_map, "ciphertext", enc.ciphertext.data(), enc.ciphertext.size());
    map_add_bstr(ct_map, "tag",        enc.tag.data(), 16);

    cbor_item_t* root = cbor_new_definite_map(5);
    map_add_uint(root, "version",    1);
    map_add_uint(root, "timeslot",   timeslot);
    map_add_uint(root, "timestamp",  timestamp);
    map_add_item(root, "ciphertext", ct_map);
    map_add_bstr(root, "signature",  sig.data(), MLDSA65_SIG_BYTES);

    Bytes out = serialize_item(root);
    cbor_decref(&root);
    return out;
}

Bytes build_guard_record_v2(const KemPubKey& key_b_pub, uint64_t timeslot,
                              const GuardPlaintext& plaintext,
                              const DsaPrivKey& key_c_priv,
                              ByteSpan dht_delegation_cert_cbor) {
    uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr));

    AesKey aead_key_arr;
    // v2 uses "inbox_dht_record" as the KDF label instead of "guard_record".
    uint8_t ts_be[8];
    uint64_t t = timeslot;
    for (int i = 7; i >= 0; --i) { ts_be[i] = t & 0xFF; t >>= 8; }
    Key32 ak = shake256_32({as_bytes(key_b_pub), ByteSpan{ts_be, 8}, as_bytes("inbox_dht_record")});
    std::copy(ak.begin(), ak.end(), aead_key_arr.begin());

    Bytes pt_cbor = encode_plaintext(plaintext);
    AesEncrypted enc = aes_encrypt(aead_key_arr, pt_cbor);

    Bytes to_sign = sign_payload_v2(timeslot, timestamp, key_b_pub,
                                     enc.nonce, enc.ciphertext, enc.tag);
    DsaSig sig    = mldsa_sign(key_c_priv, to_sign);

    cbor_item_t* ct_map = cbor_new_definite_map(3);
    map_add_bstr(ct_map, "iv",         enc.nonce.data(), 12);
    map_add_bstr(ct_map, "ciphertext", enc.ciphertext.data(), enc.ciphertext.size());
    map_add_bstr(ct_map, "tag",        enc.tag.data(), 16);

    cbor_item_t* root = cbor_new_definite_map(7);
    map_add_uint(root, "version",            2);
    map_add_uint(root, "timeslot",           timeslot);
    map_add_uint(root, "timestamp",          timestamp);
    map_add_bstr(root, "target_key_b_pubkey",key_b_pub.data(), MLKEM768_PUBKEY_BYTES);
    map_add_item(root, "ciphertext",         ct_map);
    map_add_bstr(root, "signature",          sig.data(), MLDSA65_SIG_BYTES);
    map_add_bstr(root, "dht_delegation_cert",
                 dht_delegation_cert_cbor.data(), dht_delegation_cert_cbor.size());

    Bytes out = serialize_item(root);
    cbor_decref(&root);
    return out;
}

// ── Guard record: parse ───────────────────────────────────────────────────────

GuardPlaintext parse_guard_record(ByteSpan record_cbor,
                                   const KemPubKey& key_b_pub,
                                   const DsaPubKey& key_a_pub,
                                   uint64_t timeslot) {
    auto m = load_map(record_cbor);

    auto ver_item = find_key(m, "version");
    if (!ver_item || !cbor_isa_uint(ver_item))
        throw std::runtime_error("Guard record missing version");
    uint64_t version = cbor_get_uint64(ver_item);

    auto ts_item = find_key(m, "timeslot");
    if (!ts_item) throw std::runtime_error("Missing timeslot");
    uint64_t rec_timeslot = cbor_get_uint64(ts_item);
    if (rec_timeslot != timeslot)
        throw std::runtime_error("Guard record timeslot mismatch");

    auto time_item = find_key(m, "timestamp");
    uint64_t timestamp = time_item ? cbor_get_uint64(time_item) : 0;

    // Extract ciphertext sub-map.
    auto ct_item = find_key(m, "ciphertext");
    if (!ct_item || !cbor_isa_map(ct_item))
        throw std::runtime_error("Missing ciphertext map");
    CborMap ct_m{ct_item, cbor_map_size(ct_item), cbor_map_handle(ct_item)};

    AesNonce iv;
    Bytes iv_b = bstr_or_throw(find_key(ct_m, "iv"), "iv");
    if (iv_b.size() != 12) throw std::runtime_error("iv must be 12 bytes");
    std::copy(iv_b.begin(), iv_b.end(), iv.begin());

    Bytes ct_bytes = bstr_or_throw(find_key(ct_m, "ciphertext"), "ciphertext");

    AesTag tag;
    Bytes tag_b = bstr_or_throw(find_key(ct_m, "tag"), "tag");
    if (tag_b.size() != 16) throw std::runtime_error("tag must be 16 bytes");
    std::copy(tag_b.begin(), tag_b.end(), tag.begin());

    // Verify signature before decryption.
    auto sig_item = find_key(m, "signature");
    Bytes sig_bytes = bstr_or_throw(sig_item, "signature");
    if (sig_bytes.size() != MLDSA65_SIG_BYTES)
        throw std::runtime_error("Bad signature length");
    DsaSig sig;
    std::copy(sig_bytes.begin(), sig_bytes.end(), sig.begin());

    DsaPubKey signing_pub = key_a_pub;

    if (version == 2) {
        auto dc_item = find_key(m, "dht_delegation_cert");
        Bytes dc_bytes = bstr_or_throw(dc_item, "dht_delegation_cert");
        // verify_delegation_cert validates the cert signature and expiry,
        // and returns the Key C pubkey to use for the outer record signature.
        signing_pub = verify_delegation_cert(dc_bytes, key_a_pub);
    }

    // Reconstruct sign payload and verify.
    Bytes to_verify = (version == 1)
        ? sign_payload_v1(timeslot, timestamp, iv, ct_bytes, tag)
        : sign_payload_v2(timeslot, timestamp, key_b_pub, iv, ct_bytes, tag);

    if (!mldsa_verify(signing_pub, to_verify, sig)) {
        cbor_decref(&m.root);
        throw std::runtime_error("Guard record signature invalid");
    }

    // Decrypt plaintext.
    AesKey aead_key_arr;
    Key32 ak;
    if (version == 1) {
        ak = guard_aead_key(key_b_pub, timeslot);
    } else {
        uint8_t ts_be[8];
        uint64_t t2 = timeslot;
        for (int i = 7; i >= 0; --i) { ts_be[i] = t2 & 0xFF; t2 >>= 8; }
        ak = shake256_32({as_bytes(key_b_pub), ByteSpan{ts_be, 8}, as_bytes("inbox_dht_record")});
    }
    std::copy(ak.begin(), ak.end(), aead_key_arr.begin());

    Bytes pt_cbor = aes_decrypt(aead_key_arr, iv, ct_bytes, tag);
    GuardPlaintext result = decode_plaintext(pt_cbor);
    cbor_decref(&m.root);
    return result;
}

// ── Prekey record ────────────────────────────────────────────────────────────

Bytes build_prekey_record(const KemPubKey& key_b_pub,
                           const PrekeyRecord& rec,
                           const DsaPrivKey& key_a_priv) {
    // Build prekeys array.
    cbor_item_t* pk_arr = cbor_new_definite_array(rec.prekeys.size());
    for (auto& pk : rec.prekeys) {
        cbor_item_t* item = cbor_build_bytestring(pk.data(), MLKEM768_PUBKEY_BYTES);
        cbor_array_push(pk_arr, item);
        cbor_decref(&item);
    }
    Bytes pk_arr_bytes = serialize_item(pk_arr);

    // Sign: timestamp_be8 || prekeys_cbor
    Bytes to_sign;
    to_sign.reserve(8 + pk_arr_bytes.size());
    uint64_t ts = rec.timestamp;
    for (int i = 7; i >= 0; --i) to_sign.push_back((ts >> (i*8)) & 0xFF);
    to_sign.insert(to_sign.end(), pk_arr_bytes.begin(), pk_arr_bytes.end());

    DsaSig sig = mldsa_sign(key_a_priv, to_sign);

    cbor_item_t* root = cbor_new_definite_map(3);
    map_add_uint(root, "timestamp", rec.timestamp);
    map_add_item(root, "prekeys",   pk_arr);
    map_add_bstr(root, "signature", sig.data(), MLDSA65_SIG_BYTES);

    Bytes out = serialize_item(root);
    cbor_decref(&root);
    return out;
}

PrekeyRecord parse_prekey_record(ByteSpan record_cbor,
                                  const KemPubKey& /*key_b_pub*/,
                                  const DsaPubKey& key_a_pub) {
    auto m = load_map(record_cbor);

    auto ts_item = find_key(m, "timestamp");
    if (!ts_item) throw std::runtime_error("Missing timestamp");
    uint64_t timestamp = cbor_get_uint64(ts_item);

    auto pk_arr_item = find_key(m, "prekeys");
    if (!pk_arr_item || !cbor_isa_array(pk_arr_item))
        throw std::runtime_error("Missing prekeys array");

    Bytes pk_arr_bytes = serialize_item(pk_arr_item);

    auto sig_item = find_key(m, "signature");
    Bytes sig_bytes = bstr_or_throw(sig_item, "signature");
    if (sig_bytes.size() != MLDSA65_SIG_BYTES) throw std::runtime_error("Bad sig len");
    DsaSig sig;
    std::copy(sig_bytes.begin(), sig_bytes.end(), sig.begin());

    // Verify.
    Bytes to_verify;
    to_verify.reserve(8 + pk_arr_bytes.size());
    uint64_t ts = timestamp;
    for (int i = 7; i >= 0; --i) to_verify.push_back((ts >> (i*8)) & 0xFF);
    to_verify.insert(to_verify.end(), pk_arr_bytes.begin(), pk_arr_bytes.end());

    if (!mldsa_verify(key_a_pub, to_verify, sig)) {
        cbor_decref(&m.root);
        throw std::runtime_error("Prekey record signature invalid");
    }

    // Decode prekeys.
    PrekeyRecord rec;
    rec.timestamp = timestamp;
    size_t n = cbor_array_size(pk_arr_item);
    auto handle = cbor_array_handle(pk_arr_item);
    for (size_t i = 0; i < n; ++i) {
        cbor_item_t* pki = handle[i];
        if (!cbor_isa_bytestring(pki) || cbor_bytestring_length(pki) != MLKEM768_PUBKEY_BYTES)
            throw std::runtime_error("Invalid prekey size");
        KemPubKey pk;
        std::memcpy(pk.data(), cbor_bytestring_handle(pki), MLKEM768_PUBKEY_BYTES);
        rec.prekeys.push_back(pk);
    }

    cbor_decref(&m.root);
    return rec;
}

} // namespace sw::dht
