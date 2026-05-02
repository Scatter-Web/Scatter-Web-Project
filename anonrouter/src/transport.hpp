#pragma once
#include <sw/types.hpp>
#include <functional>
#include <string>

// Minimal transport abstraction. The AnonRouter uses this to send and receive
// raw byte datagrams. The concrete implementation is UdpTransport; a QUIC
// transport can drop in without changing caller code.

namespace sw::anonrouter {

// Called for every datagram received from `peer_addr`.
using RecvCallback = std::function<void(const std::string& peer_addr, Bytes data)>;

class Transport {
public:
    virtual ~Transport() = default;

    // Bind and start receiving. Calls cb on the caller's I/O thread(s).
    virtual void start(const std::string& bind_addr, RecvCallback cb) = 0;

    // Send bytes to a "host:port" address.
    virtual void send(const std::string& peer_addr, ByteSpan data)    = 0;

    virtual void stop() = 0;
};

} // namespace sw::anonrouter
