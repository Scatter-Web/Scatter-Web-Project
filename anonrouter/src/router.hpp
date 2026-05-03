#pragma once
#include "channel.hpp"
#include "config.hpp"
#include "dht.hpp"
#include "guard.hpp"
#include "ipc_handler.hpp"
#include "tft.hpp"
#include "tunnel.hpp"
#include "udp_transport.hpp"
#include <sw/ipc/server.hpp>
#include <atomic>
#include <memory>
#include <thread>

// Router: top-level object that owns all subsystems and wires them together.
//
// Lifetime:
//   Router r(cfg);
//   r.start();
//   // ... runs until r.stop() or SIGTERM
//   r.stop();

namespace sw::anonrouter {

class Router {
public:
    explicit Router(Config cfg);
    ~Router() { stop(); }

    void start();
    void stop();
    // Block until stop() is called (e.g. from a signal handler).
    void wait();

private:
    Config cfg_;

    UdpTransport   transport_;
    GuardTable     guard_table_;
    TftEngine      tft_;
    TunnelManager  tunnels_;
    DhtClient      dht_;
    ChannelManager channels_;
    IpcHandler     ipc_handler_;
    ipc::Server    ipc_server_;

    std::atomic<bool>  running_   = false;
    std::thread        tft_thread_;
    std::thread        evict_thread_;

    // Called for every incoming UDP datagram.
    void on_datagram(const std::string& peer_addr, Bytes data);

    // Forward a cell that arrived for which we are a relay/guard.
    void relay_cell(const Cell& cell);

    // Handle CHAN_OPEN / CHAN_ACCEPT cells arriving from a direct peer.
    void on_chan_open_cell(const std::string& peer_addr, const Cell& cell);
    void on_chan_accept_cell(const Cell& cell);

    // Build and send a CHAN_OPEN cell to peer_addr.
    void send_chan_open(const MessageId& channel_id, AnonLevel anon, ChannelMode mode,
                        const std::string& peer_addr);

    // Build and send a CHAN_ACCEPT cell to peer_addr.
    void send_chan_accept(const MessageId& channel_id, const crypto::AesKey& channel_key,
                          const std::string& peer_addr);

    // IPC dispatch — intercepts channel.open and channel.accept to drive handshake.
    ipc::CborMap dispatch_ipc(const std::string& method,
                               const ipc::CborMap& params,
                               const std::string& caller);

    // Periodic TFT round (every round_seconds).
    void tft_loop();

    // Periodic guard TTL eviction (every 60 s).
    void evict_loop();

    // Fires channel.incoming push to IPC clients.
    void push_channel_incoming(const ChannelInfo& ci);
    void push_frame_recv(const MessageId& channel_id, const Bytes& frame);
};

} // namespace sw::anonrouter
