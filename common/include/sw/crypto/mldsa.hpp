#pragma once
#include <sw/types.hpp>
#include <array>

namespace sw::crypto {

constexpr size_t MLDSA65_PUBKEY_BYTES  = 1952;
constexpr size_t MLDSA65_PRIVKEY_BYTES = 4032;
constexpr size_t MLDSA65_SIG_BYTES     = 3309;

using DsaPubKey = std::array<uint8_t, MLDSA65_PUBKEY_BYTES>;
using DsaPrivKey = std::array<uint8_t, MLDSA65_PRIVKEY_BYTES>;
using DsaSig    = std::array<uint8_t, MLDSA65_SIG_BYTES>;

struct DsaKeyPair {
    DsaPubKey  pub;
    DsaPrivKey priv;
};

DsaKeyPair mldsa_keygen();
DsaSig     mldsa_sign(const DsaPrivKey& priv, ByteSpan msg);
bool       mldsa_verify(const DsaPubKey& pub, ByteSpan msg, const DsaSig& sig);

} // namespace sw::crypto
