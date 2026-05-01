#pragma once
#include <sw/ipc/codec.hpp>
#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <string>
#include <thread>

namespace sw::ipc {

// Unix domain socket IPC client.
//
// Sends framed CBOR requests and waits for matching responses by id.
// Dispatches push events to a registered callback on a background thread.
class Client {
public:
    using PushHandler = std::function<void(const std::string& event,
                                           const CborMap&     payload)>;

    explicit Client(std::string socket_path);
    ~Client();

    void connect();
    void disconnect();
    bool is_connected() const noexcept;

    // Synchronous RPC call. Throws std::runtime_error on error response or timeout.
    CborMap call(const std::string& method,
                 const CborMap&     params,
                 const std::string& caller  = "client",
                 std::chrono::milliseconds timeout = std::chrono::seconds(10));

    // Register a push event handler. Called from the receive thread.
    void on_push(PushHandler handler);

private:
    void recv_loop();

    std::string  socket_path_;
    int          fd_ = -1;
    PushHandler  push_handler_;

    std::atomic<bool>     running_{false};
    std::atomic<uint64_t> next_id_{1};
    std::thread           recv_thread_;

    std::mutex                          pending_mu_;
    std::map<uint64_t, std::promise<Response>> pending_;
};

} // namespace sw::ipc
