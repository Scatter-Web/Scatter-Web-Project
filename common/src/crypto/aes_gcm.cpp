#include <sw/crypto/aes_gcm.hpp>
#include <sodium.h>
#include <stdexcept>

static_assert(crypto_aead_aes256gcm_KEYBYTES  == sw::crypto::AES256GCM_KEY_BYTES,
              "libsodium AES-256-GCM key size mismatch");
static_assert(crypto_aead_aes256gcm_NPUBBYTES == sw::crypto::AES256GCM_NONCE_BYTES,
              "libsodium AES-256-GCM nonce size mismatch");
static_assert(crypto_aead_aes256gcm_ABYTES    == sw::crypto::AES256GCM_TAG_BYTES,
              "libsodium AES-256-GCM tag size mismatch");

namespace sw::crypto {

AesNonce aes_random_nonce() {
    AesNonce n;
    randombytes_buf(n.data(), n.size());
    return n;
}

AesEncrypted aes_encrypt(const AesKey& key, ByteSpan plaintext, ByteSpan ad) {
    if (!crypto_aead_aes256gcm_is_available())
        throw std::runtime_error("AES-256-GCM not available (no hardware AES-NI)");

    AesEncrypted out;
    out.nonce = aes_random_nonce();
    out.ciphertext.resize(plaintext.size());

    int rc = crypto_aead_aes256gcm_encrypt_detached(
        out.ciphertext.data(),
        out.tag.data(), nullptr,
        plaintext.data(), plaintext.size(),
        ad.empty() ? nullptr : ad.data(), ad.size(),
        nullptr,           // nsec (unused)
        out.nonce.data(),
        key.data());

    if (rc != 0)
        throw std::runtime_error("AES-256-GCM encrypt failed");
    return out;
}

Bytes aes_decrypt(const AesKey& key, const AesNonce& nonce,
                  ByteSpan ciphertext, const AesTag& tag, ByteSpan ad) {
    if (!crypto_aead_aes256gcm_is_available())
        throw std::runtime_error("AES-256-GCM not available (no hardware AES-NI)");

    Bytes plaintext(ciphertext.size());
    int rc = crypto_aead_aes256gcm_decrypt_detached(
        plaintext.data(), nullptr,
        ciphertext.data(), ciphertext.size(),
        tag.data(),
        ad.empty() ? nullptr : ad.data(), ad.size(),
        nonce.data(),
        key.data());

    if (rc != 0)
        throw std::runtime_error("AES-256-GCM authentication failed");
    return plaintext;
}

} // namespace sw::crypto
