#pragma once
#include <array>
#include <cstdint>
#include <ctime>
#include <span>
#include <string>
#include <vector>

namespace sw {

using Bytes    = std::vector<uint8_t>;
using ByteSpan = std::span<const uint8_t>;

using MessageId      = std::array<uint8_t, 16>;
using KeyFingerprint = std::array<uint8_t, 32>;
using SessionToken   = std::array<uint8_t, 32>;
using Nonce12        = std::array<uint8_t, 12>;
using Key32          = std::array<uint8_t, 32>;

// Timeslot rotates every 30 minutes: floor(unix_seconds / 1800)
inline uint64_t current_timeslot() {
    return static_cast<uint64_t>(std::time(nullptr)) / 1800;
}

inline uint64_t next_timeslot() {
    return current_timeslot() + 1;
}

} // namespace sw
