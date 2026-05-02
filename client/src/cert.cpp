#include "cert.hpp"
#include <sw/crypto/kdf.hpp>
#include <cbor.h>
#include <sodium.h>
#include <stdexcept>
#include <cstring>

namespace sw::client {

using namespace sw::crypto;

// ── CBOR helpers ──────────────────────────────────────────────────────────────

static Bytes cbor_to_bytes(cbor_item_t* item) {
    unsigned char* buf = nullptr;
    size_t buf_size = 0;
    size_t n = cbor_serialize_alloc(item, &buf, &buf_size);
    Bytes result(buf, buf + n);
    free(buf);
    return result;
}

static void map_add_bytes(cbor_item_t* map, const char* key,
                           const uint8_t* data, size_t len) {
    cbor_map_add(map, (struct cbor_pair){
        .key   = cbor_move(cbor_build_string(key)),
        .value = cbor_move(cbor_build_bytestring(data, len))
    });
}

static void map_add_string(cbor_item_t* map, const char* key, const char* val) {
    cbor_map_add(map, (struct cbor_pair){
        .key   = cbor_move(cbor_build_string(key)),
        .value = cbor_move(cbor_build_string(val))
    });
}

static void map_add_uint(cbor_item_t* map, const char* key, uint64_t val) {
    cbor_map_add(map, (struct cbor_pair){
        .key   = cbor_move(cbor_build_string(key)),
        .value = cbor_move(cbor_build_uint64(val))
    });
}

// Encode the map without the "signature" field for signing.
static Bytes cbor_map_without_sig(cbor_item_t* map) {
    size_t n = cbor_map_size(map);
    cbor_item_t* trimmed = cbor_new_definite_map(n);
    cbor_pair* pairs = cbor_map_handle(map);
    for (size_t i = 0; i < n; ++i) {
        const char* k = reinterpret_cast<const char*>(cbor_string_handle(pairs[i].key));
        if (strcmp(k, "signature") == 0) continue;
        cbor_map_add(trimmed, (struct cbor_pair){
            .key   = pairs[i].key,
            .value = pairs[i].value
        });
        cbor_incref(pairs[i].key);
        cbor_incref(pairs[i].value);
    }
    Bytes result = cbor_to_bytes(trimmed);
    cbor_decref(&trimmed);
    return result;
}

// ── Key C auth cert ───────────────────────────────────────────────────────────

Bytes issue_auth_cert(const DsaPrivKey& key_a_priv,
                       const DsaPubKey&  key_a_pub,
                       const DsaPubKey&  key_c_pub,
                       const std::string& device_type,
                       const std::string& device_label,
                       int64_t            now_s) {
    // device_id = SHA3-256(key_c_pubkey)
    Key32 device_id = sha3_256(ByteSpan{key_c_pub.data(), key_c_pub.size()});

    cbor_item_t* root = cbor_new_definite_map(8);
    map_add_bytes(root, "key_c_pubkey",       key_c_pub.data(),  key_c_pub.size());
    map_add_bytes(root, "owner_key_a_pubkey", key_a_pub.data(),  key_a_pub.size());
    map_add_string(root,"device_type",        device_type.c_str());
    map_add_string(root,"device_label",       device_label.c_str());
    map_add_bytes(root, "device_id",          device_id.data(),  32);
    map_add_uint(root,  "issued_at",          static_cast<uint64_t>(now_s));
    map_add_uint(root,  "expires_at",         static_cast<uint64_t>(now_s + 2592000));
    // Placeholder for signature slot (will be filled after signing)
    map_add_bytes(root, "signature",          nullptr, 0);

    Bytes to_sign = cbor_map_without_sig(root);
    DsaSig sig = mldsa_sign(key_a_priv, ByteSpan{to_sign.data(), to_sign.size()});

    // Replace signature slot.
    cbor_pair* pairs = cbor_map_handle(root);
    size_t n = cbor_map_size(root);
    for (size_t i = 0; i < n; ++i) {
        const char* k = reinterpret_cast<const char*>(cbor_string_handle(pairs[i].key));
        if (strcmp(k, "signature") == 0) {
            cbor_decref(&pairs[i].value);
            pairs[i].value = cbor_build_bytestring(sig.data(), sig.size());
            break;
        }
    }

    Bytes result = cbor_to_bytes(root);
    cbor_decref(&root);
    return result;
}

// ── DHT delegation cert ───────────────────────────────────────────────────────

Bytes issue_delegation_cert(const DsaPrivKey& key_a_priv,
                              const DsaPubKey&  key_a_pub,
                              const DsaPubKey&  key_c_pub,
                              int64_t           now_s) {
    cbor_item_t* root = cbor_new_definite_map(6);
    map_add_bytes(root, "key_c_pubkey",       key_c_pub.data(),  key_c_pub.size());
    map_add_bytes(root, "owner_key_a_pubkey", key_a_pub.data(),  key_a_pub.size());
    map_add_string(root,"scope",              "inbox");
    map_add_uint(root,  "issued_at",          static_cast<uint64_t>(now_s));
    map_add_uint(root,  "expires_at",         static_cast<uint64_t>(now_s + 2592000));
    map_add_bytes(root, "signature",          nullptr, 0);

    Bytes to_sign = cbor_map_without_sig(root);
    DsaSig sig = mldsa_sign(key_a_priv, ByteSpan{to_sign.data(), to_sign.size()});

    cbor_pair* pairs = cbor_map_handle(root);
    size_t n = cbor_map_size(root);
    for (size_t i = 0; i < n; ++i) {
        const char* k = reinterpret_cast<const char*>(cbor_string_handle(pairs[i].key));
        if (strcmp(k, "signature") == 0) {
            cbor_decref(&pairs[i].value);
            pairs[i].value = cbor_build_bytestring(sig.data(), sig.size());
            break;
        }
    }

    Bytes result = cbor_to_bytes(root);
    cbor_decref(&root);
    return result;
}

// ── Revocation notice ─────────────────────────────────────────────────────────

Bytes issue_revocation_notice(const DsaPrivKey& key_a_priv,
                               const DsaPubKey&  key_a_pub,
                               const DsaPubKey&  key_c_pub,
                               int64_t           now_s) {
    // Sign: key_c_pubkey || revoked_at (big-endian uint64)
    Bytes msg;
    msg.insert(msg.end(), key_c_pub.begin(), key_c_pub.end());
    uint8_t ts_bytes[8];
    uint64_t ts = static_cast<uint64_t>(now_s);
    for (int i = 7; i >= 0; --i) { ts_bytes[i] = ts & 0xff; ts >>= 8; }
    msg.insert(msg.end(), ts_bytes, ts_bytes + 8);

    DsaSig sig = mldsa_sign(key_a_priv, ByteSpan{msg.data(), msg.size()});

    cbor_item_t* root = cbor_new_definite_map(4);
    map_add_bytes(root, "revoked_key_c_pubkey", key_c_pub.data(), key_c_pub.size());
    map_add_bytes(root, "owner_key_a_pubkey",   key_a_pub.data(), key_a_pub.size());
    map_add_uint(root,  "revoked_at",           static_cast<uint64_t>(now_s));
    map_add_bytes(root, "signature",            sig.data(),       sig.size());

    Bytes result = cbor_to_bytes(root);
    cbor_decref(&root);
    return result;
}

// ── Contact card ──────────────────────────────────────────────────────────────

std::string encode_contact_card(const DsaPrivKey& key_a_priv,
                                  const DsaPubKey&  key_a_pub,
                                  const KemPubKey&  cr_key_b_kem_pub,
                                  const std::string& display_name,
                                  int64_t            now_s) {
    // Sign: version || key_a_pubkey || cr_key_b_kem_pubkey || display_name || created_at
    Bytes to_sign;
    uint8_t ver = 1;
    to_sign.push_back(ver);
    to_sign.insert(to_sign.end(), key_a_pub.begin(), key_a_pub.end());
    to_sign.insert(to_sign.end(), cr_key_b_kem_pub.begin(), cr_key_b_kem_pub.end());
    to_sign.insert(to_sign.end(), display_name.begin(), display_name.end());
    uint64_t ts = static_cast<uint64_t>(now_s);
    for (int i = 7; i >= 0; --i) { to_sign.push_back((ts >> (i * 8)) & 0xff); }

    DsaSig sig = mldsa_sign(key_a_priv, ByteSpan{to_sign.data(), to_sign.size()});

    cbor_item_t* root = cbor_new_definite_map(6);
    map_add_uint(root,  "version",            1);
    map_add_bytes(root, "key_a_pubkey",       key_a_pub.data(),          key_a_pub.size());
    map_add_bytes(root, "cr_key_b_kem_pubkey",cr_key_b_kem_pub.data(),   cr_key_b_kem_pub.size());
    map_add_string(root,"display_name",       display_name.c_str());
    map_add_uint(root,  "created_at",         static_cast<uint64_t>(now_s));
    map_add_bytes(root, "signature",          sig.data(),                sig.size());

    Bytes cbor_bytes = cbor_to_bytes(root);
    cbor_decref(&root);

    // base64url no-pad encode
    size_t b64_max = sodium_base64_encoded_len(cbor_bytes.size(),
                                                sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string b64(b64_max, '\0');
    sodium_bin2base64(b64.data(), b64_max,
                      cbor_bytes.data(), cbor_bytes.size(),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    // sodium_bin2base64 null-terminates; trim the null
    if (!b64.empty() && b64.back() == '\0') b64.pop_back();

    return "scatterweb://contact/" + b64;
}

std::optional<ContactCard> decode_contact_card(const std::string& uri) {
    const std::string prefix = "scatterweb://contact/";
    if (uri.substr(0, prefix.size()) != prefix) return std::nullopt;
    std::string b64 = uri.substr(prefix.size());

    // Decode base64url
    Bytes bin(b64.size()); // upper bound
    size_t bin_len = 0;
    if (sodium_base642bin(bin.data(), bin.size(),
                           b64.c_str(), b64.size(),
                           nullptr, &bin_len, nullptr,
                           sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        return std::nullopt;
    bin.resize(bin_len);

    struct cbor_load_result res;
    cbor_item_t* root = cbor_load(bin.data(), bin.size(), &res);
    if (!root || !cbor_isa_map(root)) {
        if (root) cbor_decref(&root);
        return std::nullopt;
    }

    ContactCard card{};
    cbor_pair* pairs = cbor_map_handle(root);
    size_t n = cbor_map_size(root);
    for (size_t i = 0; i < n; ++i) {
        const char* k = reinterpret_cast<const char*>(cbor_string_handle(pairs[i].key));
        cbor_item_t* v = pairs[i].value;
        if (strcmp(k, "key_a_pubkey") == 0 && cbor_isa_bytestring(v)) {
            if (cbor_bytestring_length(v) == MLDSA65_PUBKEY_BYTES)
                std::copy(cbor_bytestring_handle(v),
                          cbor_bytestring_handle(v) + MLDSA65_PUBKEY_BYTES,
                          card.key_a_pubkey.begin());
        } else if (strcmp(k, "cr_key_b_kem_pubkey") == 0 && cbor_isa_bytestring(v)) {
            if (cbor_bytestring_length(v) == MLKEM768_PUBKEY_BYTES)
                std::copy(cbor_bytestring_handle(v),
                          cbor_bytestring_handle(v) + MLKEM768_PUBKEY_BYTES,
                          card.cr_key_b_kem_pubkey.begin());
        } else if (strcmp(k, "display_name") == 0 && cbor_isa_string(v)) {
            card.display_name = std::string(
                reinterpret_cast<const char*>(cbor_string_handle(v)),
                cbor_string_length(v));
        } else if (strcmp(k, "created_at") == 0 && cbor_isa_uint(v)) {
            card.created_at = static_cast<int64_t>(cbor_get_uint64(v));
        }
    }
    cbor_decref(&root);
    return card;
}

bool verify_contact_card(const ContactCard& card, const Bytes& raw_sig,
                          const Bytes& signed_bytes) {
    if (raw_sig.size() != MLDSA65_SIG_BYTES) return false;
    DsaSig sig{};
    std::copy(raw_sig.begin(), raw_sig.end(), sig.begin());
    return mldsa_verify(card.key_a_pubkey,
                        ByteSpan{signed_bytes.data(), signed_bytes.size()}, sig);
}

// ── Delivery frame ────────────────────────────────────────────────────────────

Bytes encode_delivery_frame(const DeliveryFrame& f) {
    size_t field_count = 6;
    if (!f.sender_outbox_cert.empty()) ++field_count;

    cbor_item_t* root = cbor_new_definite_map(field_count);
    map_add_uint(root,  "version",     1);
    map_add_bytes(root, "message_id",  f.message_id.data(), f.message_id.size());
    map_add_string(root,"persistence", f.persistence.c_str());
    map_add_bytes(root, "sender_id",   f.sender_id.data(), f.sender_id.size());
    map_add_bytes(root, "cert_fingerprint", f.cert_fingerprint.data(),
                  f.cert_fingerprint.size());
    if (!f.sender_outbox_cert.empty())
        map_add_bytes(root, "sender_outbox_auth_cert",
                      f.sender_outbox_cert.data(), f.sender_outbox_cert.size());
    map_add_string(root,"envelope_type", f.envelope_type.c_str());
    map_add_bytes(root, "encrypted_envelope",
                  f.encrypted_envelope.data(), f.encrypted_envelope.size());

    Bytes result = cbor_to_bytes(root);
    cbor_decref(&root);
    return result;
}

DeliveryFrame decode_delivery_frame(ByteSpan data) {
    struct cbor_load_result res;
    cbor_item_t* root = cbor_load(data.data(), data.size(), &res);
    if (!root || !cbor_isa_map(root)) {
        if (root) cbor_decref(&root);
        throw std::runtime_error("invalid delivery_frame CBOR");
    }

    DeliveryFrame f;
    cbor_pair* pairs = cbor_map_handle(root);
    size_t n = cbor_map_size(root);
    for (size_t i = 0; i < n; ++i) {
        const char* k = reinterpret_cast<const char*>(cbor_string_handle(pairs[i].key));
        cbor_item_t* v = pairs[i].value;
        if (strcmp(k, "message_id") == 0 && cbor_isa_bytestring(v)) {
            const uint8_t* p = cbor_bytestring_handle(v);
            f.message_id.assign(p, p + cbor_bytestring_length(v));
        } else if (strcmp(k, "persistence") == 0 && cbor_isa_string(v)) {
            f.persistence = std::string(reinterpret_cast<const char*>(cbor_string_handle(v)),
                                         cbor_string_length(v));
        } else if (strcmp(k, "sender_id") == 0 && cbor_isa_bytestring(v)) {
            const uint8_t* p = cbor_bytestring_handle(v);
            f.sender_id.assign(p, p + cbor_bytestring_length(v));
        } else if (strcmp(k, "cert_fingerprint") == 0 && cbor_isa_bytestring(v)) {
            const uint8_t* p = cbor_bytestring_handle(v);
            f.cert_fingerprint.assign(p, p + cbor_bytestring_length(v));
        } else if (strcmp(k, "sender_outbox_auth_cert") == 0 && cbor_isa_bytestring(v)) {
            const uint8_t* p = cbor_bytestring_handle(v);
            f.sender_outbox_cert.assign(p, p + cbor_bytestring_length(v));
        } else if (strcmp(k, "envelope_type") == 0 && cbor_isa_string(v)) {
            f.envelope_type = std::string(reinterpret_cast<const char*>(cbor_string_handle(v)),
                                           cbor_string_length(v));
        } else if (strcmp(k, "encrypted_envelope") == 0 && cbor_isa_bytestring(v)) {
            const uint8_t* p = cbor_bytestring_handle(v);
            f.encrypted_envelope.assign(p, p + cbor_bytestring_length(v));
        }
    }
    cbor_decref(&root);
    return f;
}

} // namespace sw::client
