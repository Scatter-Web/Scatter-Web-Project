#pragma once
#include <sw/types.hpp>
#include <string>

// Minimal delivery_frame header parser.
// The Inbox treats the frame as opaque ciphertext except for these fields,
// which are needed for allowlist checks, dedup, and retention policy.

namespace sw::inbox {

struct FrameHeader {
    std::string message_id;    // 16-byte hex
    std::string sender_id;     // 32-byte hex of SHA3-256(Key A pubkey)
    std::string persistence;   // "store" | "pass_through"
    // cert_fingerprint is read but not used by Inbox (only by Outbox for ACKs).
};

// Returns false if the frame is malformed or missing required fields.
bool parse_frame_header(ByteSpan delivery_frame, FrameHeader& out);

} // namespace sw::inbox
