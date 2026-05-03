#include <sw/ipc/client.hpp>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>

namespace sw::ipc {

Client::Client(std::string socket_path)
    : socket_path_(std::move(socket_path)) {}

Client::~Client() {
    disconnect();
}

void Client::connect() {
    fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd_ < 0)
        throw std::runtime_error("socket() failed: " + std::string(strerror(errno)));

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socket_path_.size() >= sizeof(addr.sun_path))
        throw std::runtime_error("Socket path too long");
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("connect() failed: " + std::string(strerror(errno)));
    }

    running_ = true;
    recv_thread_ = std::thread([this] { recv_loop(); });
}

void Client::disconnect() {
    if (!running_.exchange(false)) return;
    if (fd_ >= 0) {
        ::shutdown(fd_, SHUT_RDWR);
        ::close(fd_);
        fd_ = -1;
    }
    if (recv_thread_.joinable())
        recv_thread_.join();

    // Fail all pending calls.
    std::lock_guard lock(pending_mu_);
    for (auto& [id, p] : pending_) {
        Response err;
        err.id = id; err.ok = false;
        err.error.code = -1; err.error.message = "disconnected";
        try { p.set_value(std::move(err)); } catch (...) {}
    }
    pending_.clear();
}

bool Client::is_connected() const noexcept { return running_; }

CborMap Client::call(const std::string& method,
                     const CborMap&     params,
                     const std::string& caller,
                     std::chrono::milliseconds timeout) {
    if (!running_)
        throw std::runtime_error("IPC client not connected: " + method);

    uint64_t id = next_id_++;

    std::promise<Response> promise;
    auto future = promise.get_future();
    {
        std::lock_guard lock(pending_mu_);
        pending_[id] = std::move(promise);
    }

    Request req{id, caller, method, params};
    write_frame(fd_, encode_request(req));

    if (future.wait_for(timeout) != std::future_status::ready) {
        std::lock_guard lock(pending_mu_);
        pending_.erase(id);
        throw std::runtime_error("IPC call timed out: " + method);
    }

    Response resp = future.get();
    if (!resp.ok)
        throw std::runtime_error("IPC error " + std::to_string(resp.error.code) +
                                  ": " + resp.error.message);
    return std::move(resp.result);
}

void Client::on_push(PushHandler handler) {
    push_handler_ = std::move(handler);
}

void Client::recv_loop() {
    while (running_) {
        Bytes payload = read_frame(fd_);
        if (payload.empty()) break;

        MsgType type = detect(payload);

        if (type == MsgType::Response) {
            Response resp = decode_response(payload);
            std::lock_guard lock(pending_mu_);
            auto it = pending_.find(resp.id);
            if (it != pending_.end()) {
                try { it->second.set_value(std::move(resp)); } catch (...) {}
                pending_.erase(it);
            }
        } else if (type == MsgType::Push && push_handler_) {
            try {
                Push push = decode_push(payload);
                push_handler_(push.event, push.payload);
            } catch (...) {}
        }
    }
    running_ = false;
}

} // namespace sw::ipc
