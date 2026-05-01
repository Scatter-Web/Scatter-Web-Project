#include <sw/crypto/kdf.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sodium.h>
#include <stdexcept>

namespace sw::crypto {

// ── SHA3-256 ──────────────────────────────────────────────────────────────────

Key32 sha3_256(ByteSpan data) {
    Key32 out;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    unsigned int len = 32;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) &&
              EVP_DigestUpdate(ctx, data.data(), data.size()) &&
              EVP_DigestFinal_ex(ctx, out.data(), &len);
    EVP_MD_CTX_free(ctx);

    if (!ok) throw std::runtime_error("SHA3-256 failed");
    return out;
}

Key32 sha3_256(std::initializer_list<ByteSpan> parts) {
    Key32 out;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    bool ok = EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 0;
    for (auto& p : parts)
        ok = ok && EVP_DigestUpdate(ctx, p.data(), p.size());

    unsigned int len = 32;
    ok = ok && EVP_DigestFinal_ex(ctx, out.data(), &len);
    EVP_MD_CTX_free(ctx);

    if (!ok) throw std::runtime_error("SHA3-256 (multi-part) failed");
    return out;
}

// ── SHAKE-256 ────────────────────────────────────────────────────────────────

Bytes shake256(ByteSpan input, size_t output_len) {
    Bytes out(output_len);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    bool ok = EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr) &&
              EVP_DigestUpdate(ctx, input.data(), input.size()) &&
              EVP_DigestFinalXOF(ctx, out.data(), output_len);
    EVP_MD_CTX_free(ctx);

    if (!ok) throw std::runtime_error("SHAKE-256 failed");
    return out;
}

Bytes shake256(std::initializer_list<ByteSpan> parts, size_t output_len) {
    Bytes out(output_len);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    bool ok = EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr) != 0;
    for (auto& p : parts)
        ok = ok && EVP_DigestUpdate(ctx, p.data(), p.size());
    ok = ok && EVP_DigestFinalXOF(ctx, out.data(), output_len);
    EVP_MD_CTX_free(ctx);

    if (!ok) throw std::runtime_error("SHAKE-256 (multi-part) failed");
    return out;
}

Key32 shake256_32(ByteSpan input) {
    auto v = shake256(input, 32);
    Key32 out;
    std::copy(v.begin(), v.end(), out.begin());
    return out;
}

Key32 shake256_32(std::initializer_list<ByteSpan> parts) {
    auto v = shake256(parts, 32);
    Key32 out;
    std::copy(v.begin(), v.end(), out.begin());
    return out;
}

// ── HMAC-SHA3-256 ────────────────────────────────────────────────────────────

Key32 hmac_sha3_256(ByteSpan key, ByteSpan data) {
    Key32 out;
    unsigned int len = 32;
    unsigned char* result = HMAC(EVP_sha3_256(),
                                  key.data(), static_cast<int>(key.size()),
                                  data.data(), data.size(),
                                  out.data(), &len);
    if (!result) throw std::runtime_error("HMAC-SHA3-256 failed");
    return out;
}

// ── Argon2id ─────────────────────────────────────────────────────────────────

Key32 argon2id(std::string_view passphrase, ByteSpan salt) {
    if (salt.size() != crypto_pwhash_SALTBYTES)
        throw std::runtime_error("Argon2id salt must be 16 bytes");

    Key32 out;
    // m=65536 KiB, t=3 — libsodium fixes parallelism at 1 internally.
    int rc = crypto_pwhash(
        out.data(), out.size(),
        passphrase.data(), passphrase.size(),
        salt.data(),
        3,                       // opslimit (t)
        65536ULL * 1024,         // memlimit (m in bytes)
        crypto_pwhash_ALG_ARGON2ID13);

    if (rc != 0)
        throw std::runtime_error("Argon2id failed (out of memory?)");
    return out;
}

} // namespace sw::crypto
