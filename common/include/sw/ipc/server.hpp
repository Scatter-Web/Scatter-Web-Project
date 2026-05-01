#pragma once
#include <sw/ipc/codec.hpp>
#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace sw::ipc {

// Unix domain socket IPC server.
//
// Accepts connections, reads framed CBOR requests, calls the handler, writes
// responses. Supports broadcasting push events to all connected clients.
// Uses one thread per connection — suitable for the handful of clients each
// daemon expects (< 5 in practice).
class Server {
public:
    // handler(method, params, caller) → result CborMap.
    // Throw std::runtime_error to send an error response (code=500).
    using Handler = std::function<CborMap(const std::string& method,
                                          const CborMap&     params,
                                          const std::string& caller)>;

    explicit Server(std::string socket_path, Handler handler);
    ~Server();

    // Bind the socket and start accepting. Non-blocking: spawns a thread.
    void start();

    // Stop accepting and close all connections. Blocks until threads exit.
    void stop();

    // Broadcast a push event to all currently connected clients.
    void push(const std::string& event, const CborMap& payload);

private:
    void accept_loop();
    void conn_loop(int fd);
    void remove_client(int fd);

    std::string socket_path_;
    Handler     handler_;
    int         listen_fd_ = -1;

    std::atomic<bool>      running_{false};
    std::thread            accept_thread_;

    std::mutex             clients_mu_;
    std::vector<int>       client_fds_;
    std::vector<std::thread> conn_threads_;
};

} // namespace sw::ipc
