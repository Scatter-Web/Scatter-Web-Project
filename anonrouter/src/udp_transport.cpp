#include "udp_transport.hpp"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <stdexcept>

namespace sw::anonrouter {

std::pair<std::string, uint16_t> UdpTransport::parse_addr(const std::string& s) {
    auto pos = s.rfind(':');
    if (pos == std::string::npos)
        throw std::runtime_error("UdpTransport: bad address: " + s);
    return {s.substr(0, pos), static_cast<uint16_t>(std::stoi(s.substr(pos + 1)))};
}

void UdpTransport::start(const std::string& bind_addr, RecvCallback cb) {
    cb_   = std::move(cb);
    sock_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_ < 0) throw std::runtime_error("UdpTransport: socket() failed");

    auto [host, port] = parse_addr(bind_addr);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (host == "0.0.0.0" || host.empty())
        sa.sin_addr.s_addr = INADDR_ANY;
    else
        inet_pton(AF_INET, host.c_str(), &sa.sin_addr);

    if (::bind(sock_, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0)
        throw std::runtime_error("UdpTransport: bind() failed on " + bind_addr);

    running_ = true;
    recv_thread_ = std::thread([this] { recv_loop(); });
}

void UdpTransport::send(const std::string& peer_addr, ByteSpan data) {
    auto [host, port] = parse_addr(peer_addr);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &dst.sin_addr) != 1) {
        // Try hostname resolution.
        addrinfo hints{}, *res = nullptr;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0 && res) {
            std::memcpy(&dst, res->ai_addr, sizeof(dst));
            dst.sin_port = htons(port);
            freeaddrinfo(res);
        }
    }
    std::lock_guard lk(send_mu_);
    ::sendto(sock_, data.data(), data.size(), 0,
             reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
}

void UdpTransport::stop() {
    if (!running_.exchange(false)) return;
    ::shutdown(sock_, SHUT_RDWR);
    if (recv_thread_.joinable()) recv_thread_.join();
    ::close(sock_);
    sock_ = -1;
}

void UdpTransport::recv_loop() {
    constexpr size_t BUF = 65536;
    std::vector<uint8_t> buf(BUF);
    sockaddr_in src{};
    socklen_t   slen = sizeof(src);
    while (running_) {
        ssize_t n = ::recvfrom(sock_, buf.data(), BUF, 0,
                               reinterpret_cast<sockaddr*>(&src), &slen);
        if (n <= 0) break;
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src.sin_addr, ipstr, sizeof(ipstr));
        std::string peer = std::string(ipstr) + ":" + std::to_string(ntohs(src.sin_port));
        cb_(peer, Bytes(buf.data(), buf.data() + n));
    }
}

} // namespace sw::anonrouter
