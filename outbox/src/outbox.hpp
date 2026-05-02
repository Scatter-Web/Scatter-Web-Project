#pragma once
#include "config.hpp"
#include "ipc_handler.hpp"
#include "store.hpp"
#include <sw/ipc/client.hpp>
#include <sw/ipc/server.hpp>
#include <atomic>
#include <thread>

namespace sw::outbox {

class Outbox {
public:
    explicit Outbox(Config cfg);
    ~Outbox() { stop(); }

    void start();
    void stop();
    void wait();

private:
    Config       cfg_;
    OutboxStore  store_;
    ipc::Client  ar_client_;
    IpcHandler   ipc_handler_;
    ipc::Server  ipc_server_;

    std::atomic<bool> running_ = false;
    std::thread       retry_thread_;
    std::thread       maintenance_thread_;

    // AnonRouter push handler: receives delivery ACKs and inbox pull requests.
    void on_ar_push(const std::string& event, const ipc::CborMap& payload);

    // Process one incoming frame (from frame.recv).
    void on_frame(const std::string& channel_id, const Bytes& body);

    // Handle delivery_ack from recipient Inbox.
    void handle_delivery_ack(const std::string& channel_id, const Bytes& body);

    // Handle outbox_poll_ack from an Inbox after it received our messages.
    void handle_poll_ack(const Bytes& body);

    // Attempt delivery of one message to one recipient Inbox.
    bool attempt_delivery(const QueuedMessage& msg, const RecipientInbox& ri);

    // Startup delivery burst: try all pending messages once.
    void startup_burst();

    // Called immediately after enqueue; tries delivery within the retry window.
    void immediate_attempt(const std::string& message_id);

    // Replicate a queued message to all sibling outboxes.
    void replicate_to_siblings(const std::string& message_id);

    // Retry loop: fires attempts for messages with next_attempt_at <= now.
    void retry_loop();

    // Periodic maintenance: expire messages, clean up.
    void maintenance_loop();

    // Ensure channel to remote Key C pubkey hex; returns channel_id.
    std::string ensure_channel(const std::string& key_c_pubkey_hex);
};

} // namespace sw::outbox
