#pragma once
#include <sw/types.hpp>
#include <sw/crypto/aes_gcm.hpp>
#include <array>
#include <cstdint>

// Cell wire format (exactly 557 bytes):
//   [0]      version      1B  (always 0x01)
//   [1]      cell_type    1B
//   [2..33]  session_tok  32B (routing handle, unencrypted for relay forwarding)
//   [34]     path_index   1B
//   [35..38] seq_num      4B  big-endian
//   [39..42] send_ts_ms   4B  big-endian (lower 32 bits of ms timestamp)
//   [43..44] garlic_len   2B  big-endian (plaintext bytes in garlic_blob)
//   [45..540] ciphertext  496B (AES-256-GCM of garlic_blob[garlic_len] + padding)
//   [541..556] gcm_tag    16B
//
// Header bytes [0..44] are used as GCM additional data (authenticated, not encrypted).
// Nonce derived from session_tok[0..7] || seq_num_be4 (12 bytes, deterministic).

namespace sw::anonrouter {

constexpr size_t CELL_SIZE               = 557;
constexpr size_t CELL_HEADER_SIZE        = 45;
constexpr size_t CELL_PLAINTEXT_SIZE     = 496;  // garlic_blob + padding
constexpr size_t CELL_TAG_SIZE           = 16;
constexpr size_t CELL_MAX_GARLIC_BYTES   = CELL_PLAINTEXT_SIZE;  // theoretical max

using Cell = std::array<uint8_t, CELL_SIZE>;

enum class CellType : uint8_t {
    DATA            = 0x01,
    RECRUIT_IN      = 0x10,
    RECRUIT_OUT     = 0x11,
    RECRUIT_RV      = 0x12,  // rendezvous
    RECRUIT_OK      = 0x13,
    RECRUIT_FULL    = 0x14,
    RECRUIT_CHOKED  = 0x15,
    DATA_ACK        = 0x20,
    KEEPALIVE       = 0x30,
    CHAN_OPEN       = 0x40,  // direct channel handshake initiation
    CHAN_ACCEPT     = 0x41,  // direct channel handshake acceptance
};

struct CellHeader {
    uint8_t      version     = 1;
    CellType     cell_type   = CellType::DATA;
    SessionToken session_tok = {};
    uint8_t      path_index  = 0;
    uint32_t     seq_num     = 0;
    uint32_t     send_ts_ms  = 0;
    uint16_t     garlic_len  = 0;
};

// Derive the 12-byte GCM nonce from session_tok and seq_num.
// Uses first 8 bytes of session_tok XOR'd with zero-padded seq_num_be8,
// then last 4 bytes = seq_num_be4. This is deterministic and unique per
// (session, sequence) pair.
crypto::AesNonce cell_nonce(const SessionToken& tok, uint32_t seq_num);

// Build and encrypt a cell. garlic_data must be <= CELL_PLAINTEXT_SIZE bytes.
Cell cell_build(const CellHeader& hdr,
                const crypto::AesKey& key,
                ByteSpan garlic_data);

// Decrypt a received cell. Throws std::runtime_error on authentication failure.
struct DecodedCell {
    CellHeader header;
    Bytes      garlic_data;  // decrypted, exactly header.garlic_len bytes
};
DecodedCell cell_decode(const Cell& cell, const crypto::AesKey& key);

// Read session_tok from the fixed offset without decryption (relay use).
SessionToken cell_session_tok(const Cell& cell);

// Replace the session_tok field in-place (relay forwarding).
void cell_set_session_tok(Cell& cell, const SessionToken& new_tok);

// Encode/decode header to/from the first CELL_HEADER_SIZE bytes.
void cell_write_header(Cell& cell, const CellHeader& hdr);
CellHeader cell_read_header(const Cell& cell);

} // namespace sw::anonrouter
