#pragma once
#include <sw/types.hpp>
#include <string>

// Parse the fields the Outbox needs from a delivery_frame CBOR blob.
// Everything else is treated as opaque ciphertext.

namespace sw::outbox {

struct DeliveryFrameHeader {
    std::string message_id;                    // 16-byte hex
    std::string recipient_key_b_kem_pubkey_hex;// hex of ML-KEM-768 pubkey
    std::string sender_outbox_key_c_pubkey_hex;// hex — used for ACK validation
};

bool parse_delivery_frame(ByteSpan frame, DeliveryFrameHeader& out);

} // namespace sw::outbox
