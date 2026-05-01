#include <sw/ipc/server.hpp>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>

namespace sw::ipc {

Server::Server(std::string socket_path, Handler handler)
    : socket_path_(std::move(socket_path))
    , handler_(std::move(handler)) {}

Server::~Server() {
    stop();
}

void Server::start() {
    listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd_ < 0)
        throw std::runtime_error("socket() failed: " + std::string(strerror(errno)));

    // Remove stale socket file.
    ::unlink(socket_path_.c_str());

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socket_path_.size() >= sizeof(addr.sun_path))
        throw std::runtime_error("Socket path too long");
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
        throw std::runtime_error("bind() failed: " + std::string(strerror(errno)));

    if (::listen(listen_fd_, 8) < 0)
        throw std::runtime_error("listen() failed: " + std::string(strerror(errno)));

    running_ = true;
    accept_thread_ = std::thread([this] { accept_loop(); });
}

void Server::stop() {
    if (!running_.exchange(false)) return;

    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }

    if (accept_thread_.joinable())
        accept_thread_.join();

    // Close all client connections and wait for their threads.
    {
        std::lock_guard lock(clients_mu_);
        for (int fd : client_fds_) {
            ::shutdown(fd, SHUT_RDWR);
            ::close(fd);
        }
        client_fds_.clear();
    }
    for (auto& t : conn_threads_)
        if (t.joinable()) t.join();
    conn_threads_.clear();

    ::unlink(socket_path_.c_str());
}

void Server::push(const std::string& event, const CborMap& payload) {
    Bytes msg = frame(encode_push(Push{event, payload}));
    std::lock_guard lock(clients_mu_);
    for (int fd : client_fds_) {
        // Best-effort: ignore per-client write errors.
        size_t done = 0;
        while (done < msg.size()) {
            ssize_t w = ::write(fd, msg.data() + done, msg.size() - done);
            if (w <= 0) break;
            done += static_cast<size_t>(w);
        }
    }
}

void Server::accept_loop() {
    while (running_) {
        int client_fd = ::accept(listen_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            if (!running_) break;
            continue;
        }
        {
            std::lock_guard lock(clients_mu_);
            client_fds_.push_back(client_fd);
        }
        conn_threads_.emplace_back([this, client_fd] { conn_loop(client_fd); });
    }
}

void Server::conn_loop(int fd) {
    while (running_) {
        Bytes payload = read_frame(fd);
        if (payload.empty()) break;  // EOF or error

        Response resp;
        try {
            Request req = decode_request(payload);
            resp.id     = req.id;
            resp.ok     = true;
            resp.result = handler_(req.method, req.params, req.caller);
        } catch (const std::exception& e) {
            resp.ok            = false;
            resp.error.code    = 500;
            resp.error.message = e.what();
        }

        try {
            write_frame(fd, encode_response(resp));
        } catch (...) {
            break;
        }
    }

    ::close(fd);
    remove_client(fd);
}

void Server::remove_client(int fd) {
    std::lock_guard lock(clients_mu_);
    client_fds_.erase(std::remove(client_fds_.begin(), client_fds_.end(), fd),
                      client_fds_.end());
}

} // namespace sw::ipc
