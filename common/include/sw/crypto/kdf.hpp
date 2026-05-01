#pragma once
#include <sw/types.hpp>
#include <initializer_list>
#include <string_view>

namespace sw::crypto {

// SHA3-256: SHA3-256(data) → 32 bytes
Key32 sha3_256(ByteSpan data);

// Multi-part SHA3-256: SHA3-256(parts[0] || parts[1] || ...) → 32 bytes
Key32 sha3_256(std::initializer_list<ByteSpan> parts);

// SHAKE-256 XOF: arbitrary output length
Bytes shake256(ByteSpan input, size_t output_len);
Bytes shake256(std::initializer_list<ByteSpan> parts, size_t output_len);

// Convenience: fixed 32-byte output (most KDF usages in the spec)
Key32 shake256_32(ByteSpan input);
Key32 shake256_32(std::initializer_list<ByteSpan> parts);

// HMAC-SHA3-256
Key32 hmac_sha3_256(ByteSpan key, ByteSpan data);

// Argon2id key derivation for keystore unlock.
// m=65536 KiB, t=3, p=1 (libsodium fixes p=1).
Key32 argon2id(std::string_view passphrase, ByteSpan salt);

// Helpers: convert string_view/array to ByteSpan for multi-part calls
inline ByteSpan as_bytes(std::string_view sv) {
    return {reinterpret_cast<const uint8_t*>(sv.data()), sv.size()};
}

template<size_t N>
inline ByteSpan as_bytes(const std::array<uint8_t, N>& arr) {
    return {arr.data(), N};
}

} // namespace sw::crypto
