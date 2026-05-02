#pragma once
#include <sw/types.hpp>
#include <sw/crypto/mldsa.hpp>
#include <sw/crypto/mlkem.hpp>
#include <optional>
#include <string>

namespace sw::client {

// ── Key C cert issuance ───────────────────────────────────────────────────────

// Returns CBOR-encoded key_c_auth_cert signed by Key A.
Bytes issue_auth_cert(const crypto::DsaPrivKey& key_a_priv,
                      const crypto::DsaPubKey&  key_a_pub,
                      const crypto::DsaPubKey&  key_c_pub,
                      const std::string&         device_type,
                      const std::string&         device_label,
                      int64_t                    now_s);

// Returns CBOR-encoded dht_delegation_cert signed by Key A (Inbox only).
Bytes issue_delegation_cert(const crypto::DsaPrivKey& key_a_priv,
                             const crypto::DsaPubKey&  key_a_pub,
                             const crypto::DsaPubKey&  key_c_pub,
                             int64_t                   now_s);

// Returns CBOR-encoded key_c_revocation signed by Key A.
Bytes issue_revocation_notice(const crypto::DsaPrivKey& key_a_priv,
                               const crypto::DsaPubKey&  key_a_pub,
                               const crypto::DsaPubKey&  key_c_pub,
                               int64_t                   now_s);

// ── Contact card ──────────────────────────────────────────────────────────────

struct ContactCard {
    crypto::DsaPubKey  key_a_pubkey;
    crypto::KemPubKey  cr_key_b_kem_pubkey;
    std::string        display_name;
    int64_t            created_at;
};

// Returns "scatterweb://contact/<base64url_noPad(CBOR)>"
std::string encode_contact_card(const crypto::DsaPrivKey& key_a_priv,
                                 const crypto::DsaPubKey&  key_a_pub,
                                 const crypto::KemPubKey&  cr_key_b_kem_pub,
                                 const std::string&         display_name,
                                 int64_t                    now_s);

// Parses the URI; returns nullopt on invalid input.
std::optional<ContactCard> decode_contact_card(const std::string& uri);

// Verify the card's signature and return true if valid.
bool verify_contact_card(const ContactCard& card, const Bytes& raw_sig,
                          const Bytes& signed_bytes);

// ── Delivery frame ────────────────────────────────────────────────────────────

struct DeliveryFrame {
    Bytes       message_id;          // 16 bytes
    std::string persistence;         // "store" | "pass_through"
    Bytes       sender_id;           // 32 bytes SHA3-256(Key A pubkey)
    Bytes       cert_fingerprint;    // 32 bytes SHA3-256(auth_cert)
    Bytes       sender_outbox_cert;  // may be empty (omitted)
    std::string envelope_type;       // "ratchet" | "sender_key"
    Bytes       encrypted_envelope;
};

Bytes encode_delivery_frame(const DeliveryFrame& f);
DeliveryFrame decode_delivery_frame(ByteSpan data);

} // namespace sw::client
