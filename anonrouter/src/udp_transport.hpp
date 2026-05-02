#pragma once
#include "transport.hpp"
#include <atomic>
#include <thread>

namespace sw::anonrouter {

// UDP datagram transport. Good enough for development and testing.
// Each incoming datagram fires the RecvCallback from the recv thread.
// send() is thread-safe (uses one UDP socket with a mutex-guarded sendto).

class UdpTransport final : public Transport {
public:
    UdpTransport() = default;
    ~UdpTransport() override { stop(); }

    void start(const std::string& bind_addr, RecvCallback cb) override;
    void send(const std::string& peer_addr, ByteSpan data)    override;
    void stop()                                                override;

private:
    int             sock_      = -1;
    std::atomic<bool> running_ = false;
    std::thread     recv_thread_;
    std::mutex      send_mu_;
    RecvCallback    cb_;

    void recv_loop();
    // Returns {host, port} parsed from "host:port".
    static std::pair<std::string,uint16_t> parse_addr(const std::string& s);
};

} // namespace sw::anonrouter
