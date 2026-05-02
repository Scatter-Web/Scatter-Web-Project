#pragma once
#include <sw/types.hpp>
#include <cstdint>
#include <optional>
#include <vector>

// Garlic encoding: a garlic_blob is a CBOR array of "cloves". Each clove
// carries an independent logical payload (message fragment, ACK, control).
//
// The garlic_blob is AES-256-GCM encrypted end-to-end by the channel layer;
// relay nodes never see clove contents — only the outer cell header.

namespace sw::anonrouter {

enum class CloveType : uint8_t {
    DATA      = 0x01,  // application payload fragment
    ACK       = 0x02,  // reliability ACK
    HEARTBEAT = 0x03,  // path health probe
    CTRL      = 0x04,  // channel control (CHAN_OPEN, CHAN_ACCEPT, etc.)
};

struct FragInfo {
    uint32_t clove_id  = 0;  // reassembly group ID
    uint16_t idx       = 0;  // fragment index within group
    uint16_t total     = 0;  // total fragments in group
};

struct Clove {
    CloveType          type       = CloveType::DATA;
    MessageId          channel_id = {};   // 16-byte channel UUID (zero = no channel)
    std::optional<FragInfo> frag;         // present only for DATA with fragmentation
    Bytes              payload;
};

// Encode a list of cloves into a CBOR garlic_blob byte string.
// Returns empty on encoding failure.
Bytes garlic_encode(const std::vector<Clove>& cloves);

// Decode a CBOR garlic_blob into cloves. Returns empty on parse/auth error.
std::vector<Clove> garlic_decode(ByteSpan blob);

} // namespace sw::anonrouter
