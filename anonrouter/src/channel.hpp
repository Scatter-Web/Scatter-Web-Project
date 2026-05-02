#pragma once
#include "cell.hpp"
#include "garlic.hpp"
#include "tunnel.hpp"
#include <sw/crypto/aes_gcm.hpp>
#include <sw/crypto/mlkem.hpp>
#include <atomic>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

// Channel abstraction: bidirectional ordered stream of frames between two
// peers, transparent to tunnel/guard infrastructure.

namespace sw::anonrouter {

enum class AnonLevel : uint8_t {
    DIRECT   = 0,    // Level 0: direct QUIC
    RENDEZVOUS = 1,  // Level 0.5
    ANONYMOUS  = 2,  // Level 1: single-hop guards (default)
};

enum class ChannelMode : uint8_t {
    DATAGRAM = 0,   // fire-and-forget
    MESSAGE  = 1,   // reliable, 2–3 paths
    STREAM   = 2,   // unreliable + FEC, 5–6 paths
};

enum class ChannelState : uint8_t {
    OPENING   = 0,
    OPEN      = 1,
    UPGRADING = 2,
    CLOSED    = 3,
};

struct GuardRef {
    std::string  node_id;
    SessionToken session_tok;
};

struct ChannelInfo {
    MessageId    channel_id     = {};
    std::string  remote_pubkey_hex;   // hex of remote Key H pubkey
    AnonLevel    anon_level     = AnonLevel::ANONYMOUS;
    ChannelMode  mode           = ChannelMode::MESSAGE;
    ChannelState state          = ChannelState::OPENING;
    crypto::AesKey channel_key  = {};  // shared channel_key from handshake
    uint32_t     send_seq       = 0;
    uint32_t     recv_seq       = 0;
    int64_t      rtt_ms         = 0;
    // Inbound guard this peer recruited (remote sends to us here).
    std::optional<GuardRef> my_inbound_guard;
    // Outbound guard: we send cells here to reach remote's inbound guard.
    std::optional<GuardRef> remote_inbound_guard;
};

// Callback fired when a frame arrives on a channel.
using FrameCallback = std::function<void(const MessageId& channel_id, Bytes frame)>;

// Callback fired on channel state changes.
using StateCallback = std::function<void(const MessageId& channel_id, ChannelState state)>;

class ChannelManager {
public:
    ChannelManager(TunnelManager& tunnels, Transport& transport)
        : tunnels_(tunnels), transport_(transport) {}

    void set_frame_cb(FrameCallback cb)  { frame_cb_  = std::move(cb); }
    void set_state_cb(StateCallback cb)  { state_cb_  = std::move(cb); }

    // Initiate a channel open; state transitions to OPEN asynchronously.
    MessageId open(const std::string& remote_pubkey_hex,
                   AnonLevel anon_level,
                   ChannelMode mode);

    // Accept an incoming CHAN_OPEN (identified by channel_id from push event).
    bool accept(const MessageId& channel_id);

    // Reject an incoming CHAN_OPEN.
    void reject(const MessageId& channel_id);

    // Upgrade mode (e.g. MESSAGE → STREAM).
    bool upgrade(const MessageId& channel_id, ChannelMode new_mode,
                 const crypto::AesKey& csk);

    // Send application payload on a channel.
    bool send(const MessageId& channel_id, ByteSpan payload);

    // Close and remove a channel.
    void close(const MessageId& channel_id);

    std::optional<ChannelInfo> get(const MessageId& channel_id) const;
    std::vector<ChannelInfo>   list() const;

    // Called by the router when a cell arrives that belongs to one of our channels.
    void on_cell(const Cell& cell);

    // Called by the router for incoming CHAN_OPEN cells (fires state_cb).
    void on_chan_open(const Bytes& payload);

    // Called for CHAN_ACCEPT cells.
    void on_chan_accept(const Bytes& payload);

private:
    TunnelManager& tunnels_;
    Transport&     transport_;
    FrameCallback  frame_cb_;
    StateCallback  state_cb_;

    mutable std::mutex mu_;
    // keyed by hex(channel_id)
    std::unordered_map<std::string, ChannelInfo> channels_;

    static std::string chan_key(const MessageId& id);

    void set_state(const MessageId& id, ChannelState s);
    void deliver_frame(const MessageId& id, Bytes frame);
};

} // namespace sw::anonrouter
