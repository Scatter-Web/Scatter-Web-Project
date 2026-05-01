#pragma once
#include <sw/types.hpp>
#include <array>

namespace sw::crypto {

constexpr size_t AES256GCM_KEY_BYTES   = 32;
constexpr size_t AES256GCM_NONCE_BYTES = 12;
constexpr size_t AES256GCM_TAG_BYTES   = 16;

using AesKey   = std::array<uint8_t, AES256GCM_KEY_BYTES>;
using AesNonce = std::array<uint8_t, AES256GCM_NONCE_BYTES>;
using AesTag   = std::array<uint8_t, AES256GCM_TAG_BYTES>;

struct AesEncrypted {
    Bytes   ciphertext;
    AesTag  tag;
    AesNonce nonce;  // caller may need it stored alongside ciphertext
};

// Generate a random 12-byte nonce.
AesNonce aes_random_nonce();

// Encrypt plaintext with optional additional data. Nonce is generated internally.
AesEncrypted aes_encrypt(const AesKey& key, ByteSpan plaintext, ByteSpan ad = {});

// Decrypt. Returns plaintext or throws std::runtime_error on authentication failure.
Bytes aes_decrypt(const AesKey& key, const AesNonce& nonce,
                  ByteSpan ciphertext, const AesTag& tag, ByteSpan ad = {});

} // namespace sw::crypto
