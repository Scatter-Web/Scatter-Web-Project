#include "channel.hpp"
#include <sw/crypto/kdf.hpp>
#include <sodium.h>
#include <cbor.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <cstring>

namespace sw::anonrouter {

static uint64_t safe_cbor_uint(const cbor_item_t* item) {
    switch (cbor_int_get_width(item)) {
        case CBOR_INT_8:  return cbor_get_uint8(item);
        case CBOR_INT_16: return cbor_get_uint16(item);
        case CBOR_INT_32: return cbor_get_uint32(item);
        case CBOR_INT_64: return cbor_get_uint64(item);
    }
    return 0;
}

using namespace sw::crypto;

static std::string to_hex(const uint8_t* d, size_t n) {
    std::ostringstream ss;
    for (size_t i = 0; i < n; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)d[i];
    return ss.str();
}

std::string ChannelManager::chan_key(const MessageId& id) {
    return to_hex(id.data(), id.size());
}

void ChannelManager::set_state(const MessageId& id, ChannelState s) {
    {
        std::lock_guard lk(mu_);
        auto it = channels_.find(chan_key(id));
        if (it != channels_.end()) it->second.state = s;
    }
    if (state_cb_) state_cb_(id, s);
}

void ChannelManager::deliver_frame(const MessageId& id, Bytes frame) {
    if (frame_cb_) frame_cb_(id, std::move(frame));
}

MessageId ChannelManager::open(const std::string& remote_pubkey_hex,
                                AnonLevel anon_level,
                                ChannelMode mode,
                                const std::string& peer_addr) {
    ChannelInfo ci;
    randombytes_buf(ci.channel_id.data(), ci.channel_id.size());
    ci.remote_pubkey_hex = remote_pubkey_hex;
    ci.anon_level        = anon_level;
    ci.mode              = mode;
    ci.state             = ChannelState::OPENING;
    ci.peer_addr         = peer_addr;

    // Generate a temporary channel key; replaced with acceptor's key on CHAN_ACCEPT.
    randombytes_buf(ci.channel_key.data(), ci.channel_key.size());

    {
        std::lock_guard lk(mu_);
        channels_[chan_key(ci.channel_id)] = ci;
    }
    return ci.channel_id;
}

MessageId ChannelManager::register_incoming(const MessageId& channel_id,
                                             const std::string& peer_addr,
                                             AnonLevel anon_level,
                                             ChannelMode mode) {
    ChannelInfo ci;
    ci.channel_id  = channel_id;
    ci.peer_addr   = peer_addr;
    ci.anon_level  = anon_level;
    ci.mode        = mode;
    ci.state       = ChannelState::OPENING;
    {
        std::lock_guard lk(mu_);
        channels_[chan_key(channel_id)] = ci;
    }
    if (state_cb_) state_cb_(channel_id, ChannelState::OPENING);
    return channel_id;
}

bool ChannelManager::accept(const MessageId& channel_id, crypto::AesKey& out_key) {
    std::lock_guard lk(mu_);
    auto it = channels_.find(chan_key(channel_id));
    if (it == channels_.end()) return false;
    // Generate the shared channel key; send it back to initiator in CHAN_ACCEPT.
    randombytes_buf(it->second.channel_key.data(), it->second.channel_key.size());
    it->second.state = ChannelState::OPEN;
    out_key = it->second.channel_key;
    return true;
}

bool ChannelManager::accept(const MessageId& channel_id) {
    crypto::AesKey unused{};
    return accept(channel_id, unused);
}

void ChannelManager::reject(const MessageId& channel_id) {
    close(channel_id);
}

bool ChannelManager::upgrade(const MessageId& channel_id, ChannelMode new_mode,
                              const AesKey& csk) {
    std::lock_guard lk(mu_);
    auto it = channels_.find(chan_key(channel_id));
    if (it == channels_.end()) return false;
    it->second.mode       = new_mode;
    it->second.channel_key = csk;
    it->second.state      = ChannelState::OPEN;
    return true;
}

bool ChannelManager::send(const MessageId& channel_id, ByteSpan payload) {
    ChannelInfo ci;
    {
        std::lock_guard lk(mu_);
        auto it = channels_.find(chan_key(channel_id));
        if (it == channels_.end() || it->second.state != ChannelState::OPEN)
            return false;
        ci = it->second;
    }

    // Encrypt payload with channel_key.
    AesNonce nonce = aes_random_nonce();
    auto enc = aes_encrypt(ci.channel_key, payload, {});

    // Pack into a DATA garlic clove.
    Clove clove;
    clove.type       = CloveType::DATA;
    clove.channel_id = channel_id;
    clove.payload    = enc.ciphertext;
    // Prepend nonce + tag (16 B) to ciphertext for the receiver.
    Bytes blob;
    blob.insert(blob.end(), enc.nonce.begin(), enc.nonce.end());
    blob.insert(blob.end(), enc.tag.begin(),   enc.tag.end());
    blob.insert(blob.end(), enc.ciphertext.begin(), enc.ciphertext.end());
    clove.payload = std::move(blob);

    Bytes garlic = garlic_encode({clove});
    if (garlic.empty()) return false;

    // Build cell.
    CellHeader hdr;
    hdr.cell_type  = CellType::DATA;
    hdr.garlic_len = static_cast<uint16_t>(std::min(garlic.size(), (size_t)CELL_PLAINTEXT_SIZE));
    {
        std::lock_guard lk(mu_);
        auto it = channels_.find(chan_key(channel_id));
        if (it == channels_.end()) return false;
        if (it->second.my_inbound_guard) {
            hdr.session_tok = it->second.my_inbound_guard->session_tok;
        } else if (it->second.anon_level == AnonLevel::DIRECT) {
            // For DIRECT channels use channel_id as the first 16 bytes of
            // session_tok so the receiver can route by channel_id lookup.
            hdr.session_tok = {};
            std::copy(it->second.channel_id.begin(),
                      it->second.channel_id.end(),
                      hdr.session_tok.begin());
        } else {
            hdr.session_tok = {};
        }
        hdr.seq_num = it->second.send_seq++;
    }

    ByteSpan gspan{garlic.data(), hdr.garlic_len};
    Cell cell = cell_build(hdr, ci.channel_key, gspan);

    if (ci.anon_level == AnonLevel::DIRECT && !ci.peer_addr.empty()) {
        transport_.send(ci.peer_addr, ByteSpan{cell.data(), cell.size()});
        return true;
    }
    if (ci.remote_inbound_guard) {
        tunnels_.forward_via_outbound(ci.remote_inbound_guard->session_tok, cell);
    }
    return true;
}

void ChannelManager::close(const MessageId& channel_id) {
    {
        std::lock_guard lk(mu_);
        channels_.erase(chan_key(channel_id));
    }
    if (state_cb_) state_cb_(channel_id, ChannelState::CLOSED);
}

std::optional<ChannelInfo> ChannelManager::get(const MessageId& channel_id) const {
    std::lock_guard lk(mu_);
    auto it = channels_.find(chan_key(channel_id));
    if (it == channels_.end()) return std::nullopt;
    return it->second;
}

std::vector<ChannelInfo> ChannelManager::list() const {
    std::lock_guard lk(mu_);
    std::vector<ChannelInfo> out;
    out.reserve(channels_.size());
    for (auto& [k, v] : channels_) out.push_back(v);
    return out;
}

void ChannelManager::on_cell(const Cell& cell) {
    SessionToken tok = cell_session_tok(cell);

    // For DIRECT channels the session_tok encodes the channel_id in bytes [0..15].
    MessageId direct_id{};
    std::copy(tok.begin(), tok.begin() + 16, direct_id.begin());

    std::lock_guard lk(mu_);
    for (auto& [k, ci] : channels_) {
        bool matches = (ci.my_inbound_guard && ci.my_inbound_guard->session_tok == tok)
                    || (ci.anon_level == AnonLevel::DIRECT
                        && ci.state == ChannelState::OPEN
                        && ci.channel_id == direct_id);
        if (matches) {
            DecodedCell dc = cell_decode(cell, ci.channel_key);
            auto cloves = garlic_decode(ByteSpan{dc.garlic_data.data(), dc.garlic_data.size()});
            for (auto& clove : cloves) {
                if (clove.type == CloveType::DATA && clove.payload.size() > 28) {
                    // Extract nonce(12) + tag(16) + ciphertext.
                    AesNonce nonce{};
                    std::copy(clove.payload.begin(), clove.payload.begin() + 12, nonce.begin());
                    AesTag tag{};
                    std::copy(clove.payload.begin() + 12, clove.payload.begin() + 28, tag.begin());
                    ByteSpan ct{clove.payload.data() + 28, clove.payload.size() - 28};
                    try {
                        Bytes plain = aes_decrypt(ci.channel_key, nonce, ct, tag, {});
                        if (frame_cb_) frame_cb_(ci.channel_id, std::move(plain));
                    } catch (...) {}
                }
            }
            break;
        }
    }
}

void ChannelManager::on_chan_open(const Bytes& payload) {
    // Parse CHAN_OPEN payload (CBOR) and register the pending channel.
    struct cbor_load_result res{};
    cbor_item_t* root = cbor_load(payload.data(), payload.size(), &res);
    if (!root || !cbor_isa_map(root)) { if (root) cbor_decref(&root); return; }

    ChannelInfo ci;
    ci.state = ChannelState::OPENING;

    for (size_t i = 0; i < cbor_map_size(root); ++i) {
        auto p = cbor_map_handle(root)[i];
        std::string k(reinterpret_cast<char*>(cbor_string_handle(p.key)),
                      cbor_string_length(p.key));
        if (k == "channel_id" && cbor_isa_bytestring(p.value)
                && cbor_bytestring_length(p.value) == 16)
            std::memcpy(ci.channel_id.data(), cbor_bytestring_handle(p.value), 16);
        else if (k == "remote_pubkey" && cbor_isa_string(p.value))
            ci.remote_pubkey_hex.assign(
                reinterpret_cast<char*>(cbor_string_handle(p.value)),
                cbor_string_length(p.value));
        else if (k == "anon_level")
            ci.anon_level = static_cast<AnonLevel>(safe_cbor_uint(p.value));
        else if (k == "mode")
            ci.mode = static_cast<ChannelMode>(safe_cbor_uint(p.value));
    }
    cbor_decref(&root);

    std::lock_guard lk(mu_);
    channels_[chan_key(ci.channel_id)] = ci;
    // State callback (channel.incoming) fires via on_chan_open caller (router).
}

void ChannelManager::on_chan_accept(const Bytes& payload) {
    struct cbor_load_result res{};
    cbor_item_t* root = cbor_load(payload.data(), payload.size(), &res);
    if (!root || !cbor_isa_map(root)) { if (root) cbor_decref(&root); return; }

    MessageId  channel_id{};
    AesKey     channel_key{};

    for (size_t i = 0; i < cbor_map_size(root); ++i) {
        auto p = cbor_map_handle(root)[i];
        std::string k(reinterpret_cast<char*>(cbor_string_handle(p.key)),
                      cbor_string_length(p.key));
        if (k == "channel_id" && cbor_isa_bytestring(p.value)
                && cbor_bytestring_length(p.value) == 16)
            std::memcpy(channel_id.data(), cbor_bytestring_handle(p.value), 16);
        else if (k == "channel_key" && cbor_isa_bytestring(p.value)
                && cbor_bytestring_length(p.value) == 32)
            std::memcpy(channel_key.data(), cbor_bytestring_handle(p.value), 32);
    }
    cbor_decref(&root);

    std::lock_guard lk(mu_);
    auto it = channels_.find(chan_key(channel_id));
    if (it == channels_.end()) return;
    it->second.channel_key = channel_key;
    it->second.state       = ChannelState::OPEN;
}

} // namespace sw::anonrouter
