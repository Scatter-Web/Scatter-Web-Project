#pragma once
#include <sw/types.hpp>
#include <array>

namespace sw::crypto {

constexpr size_t MLKEM768_PUBKEY_BYTES  = 1184;
constexpr size_t MLKEM768_PRIVKEY_BYTES = 2400;
constexpr size_t MLKEM768_CT_BYTES      = 1088;
constexpr size_t MLKEM768_SS_BYTES      = 32;

using KemPubKey  = std::array<uint8_t, MLKEM768_PUBKEY_BYTES>;
using KemPrivKey = std::array<uint8_t, MLKEM768_PRIVKEY_BYTES>;
using KemCt      = std::array<uint8_t, MLKEM768_CT_BYTES>;
using KemSS      = std::array<uint8_t, MLKEM768_SS_BYTES>;

struct KemKeyPair {
    KemPubKey  pub;
    KemPrivKey priv;
};

struct KemEncapsulated {
    KemCt ct;
    KemSS ss;
};

KemKeyPair     mlkem_keygen();
KemEncapsulated mlkem_encapsulate(const KemPubKey& pub);
KemSS          mlkem_decapsulate(const KemPrivKey& priv, const KemCt& ct);

} // namespace sw::crypto
