#include "cell.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <sodium.h>
#include <stdexcept>

namespace sw::anonrouter {

using namespace sw::crypto;

// ── Nonce derivation ──────────────────────────────────────────────────────────

AesNonce cell_nonce(const SessionToken& tok, uint32_t seq_num) {
    AesNonce n{};
    // bytes [0..7]: first 8 bytes of session_tok
    std::copy(tok.begin(), tok.begin() + 8, n.begin());
    // bytes [8..11]: seq_num big-endian
    n[8]  = (seq_num >> 24) & 0xFF;
    n[9]  = (seq_num >> 16) & 0xFF;
    n[10] = (seq_num >>  8) & 0xFF;
    n[11] = (seq_num      ) & 0xFF;
    return n;
}

// ── Header encode / decode ────────────────────────────────────────────────────

void cell_write_header(Cell& cell, const CellHeader& hdr) {
    cell[0] = hdr.version;
    cell[1] = static_cast<uint8_t>(hdr.cell_type);
    std::copy(hdr.session_tok.begin(), hdr.session_tok.end(), cell.begin() + 2);
    cell[34] = hdr.path_index;
    cell[35] = (hdr.seq_num >> 24) & 0xFF;
    cell[36] = (hdr.seq_num >> 16) & 0xFF;
    cell[37] = (hdr.seq_num >>  8) & 0xFF;
    cell[38] = (hdr.seq_num      ) & 0xFF;
    cell[39] = (hdr.send_ts_ms >> 24) & 0xFF;
    cell[40] = (hdr.send_ts_ms >> 16) & 0xFF;
    cell[41] = (hdr.send_ts_ms >>  8) & 0xFF;
    cell[42] = (hdr.send_ts_ms      ) & 0xFF;
    cell[43] = (hdr.garlic_len >> 8) & 0xFF;
    cell[44] = (hdr.garlic_len     ) & 0xFF;
}

CellHeader cell_read_header(const Cell& cell) {
    CellHeader hdr;
    hdr.version    = cell[0];
    hdr.cell_type  = static_cast<CellType>(cell[1]);
    std::copy(cell.begin() + 2, cell.begin() + 34, hdr.session_tok.begin());
    hdr.path_index = cell[34];
    hdr.seq_num    = (uint32_t(cell[35]) << 24) | (uint32_t(cell[36]) << 16)
                   | (uint32_t(cell[37]) <<  8) |  uint32_t(cell[38]);
    hdr.send_ts_ms = (uint32_t(cell[39]) << 24) | (uint32_t(cell[40]) << 16)
                   | (uint32_t(cell[41]) <<  8) |  uint32_t(cell[42]);
    hdr.garlic_len = (uint16_t(cell[43]) << 8) | uint16_t(cell[44]);
    return hdr;
}

// ── Build / decode ────────────────────────────────────────────────────────────

Cell cell_build(const CellHeader& hdr, const AesKey& key, ByteSpan garlic_data) {
    if (garlic_data.size() > CELL_PLAINTEXT_SIZE)
        throw std::runtime_error("garlic_data exceeds cell payload capacity");

    Cell cell{};
    cell_write_header(cell, hdr);

    // Build plaintext payload: garlic_data + zero padding to CELL_PLAINTEXT_SIZE.
    std::array<uint8_t, CELL_PLAINTEXT_SIZE> plaintext{};
    std::copy(garlic_data.begin(), garlic_data.end(), plaintext.begin());

    AesNonce nonce = cell_nonce(hdr.session_tok, hdr.seq_num);

    // Header bytes are additional authenticated data.
    ByteSpan ad{cell.data(), CELL_HEADER_SIZE};

    AesEncrypted enc = aes_encrypt(key, plaintext, ad);
    // The returned AesEncrypted has a random nonce but we use the deterministic one.
    // Re-encrypt using the deterministic nonce via the raw libsodium call.
    // Since aes_encrypt always generates a random nonce internally, we call aes_decrypt
    // with the deterministic nonce separately. Instead, we encrypt directly here:

    // We need to bypass aes_encrypt's random nonce. Use libsodium directly.
    // (Included via aes_gcm.hpp → sodium.h transitively through the link.)
    // For correctness, call the explicit function:
    AesTag tag;
    Bytes ciphertext(CELL_PLAINTEXT_SIZE);
    // Use libsodium directly (aes_gcm.hpp exposes the headers we need).
    if (crypto_aead_aes256gcm_encrypt_detached(
            ciphertext.data(), tag.data(), nullptr,
            plaintext.data(), CELL_PLAINTEXT_SIZE,
            ad.data(), ad.size(),
            nullptr,
            nonce.data(),
            key.data()) != 0)
        throw std::runtime_error("cell_build: AES-GCM encrypt failed");

    std::copy(ciphertext.begin(), ciphertext.end(), cell.begin() + CELL_HEADER_SIZE);
    std::copy(tag.begin(), tag.end(), cell.begin() + CELL_HEADER_SIZE + CELL_PLAINTEXT_SIZE);
    return cell;
}

DecodedCell cell_decode(const Cell& cell, const AesKey& key) {
    CellHeader hdr = cell_read_header(cell);

    AesNonce nonce = cell_nonce(hdr.session_tok, hdr.seq_num);
    ByteSpan ad{cell.data(), CELL_HEADER_SIZE};

    const uint8_t* ct_ptr  = cell.data() + CELL_HEADER_SIZE;
    const uint8_t* tag_ptr = ct_ptr + CELL_PLAINTEXT_SIZE;

    std::array<uint8_t, CELL_PLAINTEXT_SIZE> plaintext{};
    if (crypto_aead_aes256gcm_decrypt_detached(
            plaintext.data(), nullptr,
            ct_ptr, CELL_PLAINTEXT_SIZE,
            tag_ptr,
            ad.data(), ad.size(),
            nonce.data(),
            key.data()) != 0)
        throw std::runtime_error("cell_decode: AES-GCM authentication failed");

    if (hdr.garlic_len > CELL_PLAINTEXT_SIZE)
        throw std::runtime_error("cell_decode: garlic_len out of bounds");

    DecodedCell result;
    result.header     = hdr;
    result.garlic_data.assign(plaintext.begin(), plaintext.begin() + hdr.garlic_len);
    return result;
}

SessionToken cell_session_tok(const Cell& cell) {
    SessionToken tok;
    std::copy(cell.begin() + 2, cell.begin() + 34, tok.begin());
    return tok;
}

void cell_set_session_tok(Cell& cell, const SessionToken& new_tok) {
    std::copy(new_tok.begin(), new_tok.end(), cell.begin() + 2);
}

} // namespace sw::anonrouter
