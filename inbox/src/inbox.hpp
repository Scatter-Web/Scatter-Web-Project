#pragma once
#include "config.hpp"
#include "ipc_handler.hpp"
#include "store.hpp"
#include <sw/ipc/client.hpp>
#include <sw/ipc/server.hpp>
#include <atomic>
#include <thread>

namespace sw::inbox {

class Inbox {
public:
    explicit Inbox(Config cfg);
    ~Inbox() { stop(); }

    void start();
    void stop();
    void wait();

private:
    Config       cfg_;
    InboxStore   store_;
    ipc::Client  ar_client_;    // connection to AnonRouter
    IpcHandler   ipc_handler_;
    ipc::Server  ipc_server_;

    std::atomic<bool> running_ = false;
    std::thread       maintenance_thread_;

    // Receive frame.recv push events from AnonRouter.
    void on_ar_push(const std::string& event, const ipc::CborMap& payload);

    // Process one delivery_frame received from the network.
    void process_delivery_frame(const std::string& channel_id, const Bytes& body);

    // Send delivery_ack back to the sender via AnonRouter.
    void send_ack(const std::string& channel_id, const std::string& message_id);

    // Replicate a stored message to all sibling Inboxes.
    void replicate_to_siblings(const std::string& message_id);

    // Handle inbox_replication_frame received from a sibling.
    void handle_replication_frame(const Bytes& body);

    // Handle outbox_poll request from a known Outbox.
    void handle_outbox_poll(const std::string& channel_id, const Bytes& body);

    // Poll all known_outboxes for messages waiting for us.
    void poll_known_outboxes();

    // Fetch current guard info from AnonRouter.
    ipc::CborMap guard_info();

    // Periodic: expire stale messages, retry pending replications.
    void maintenance_loop();

    // Ensure an AnonRouter channel to the given Key C pubkey hex is open;
    // returns channel_id (hex).
    std::string ensure_channel(const std::string& key_c_pubkey_hex);
};

} // namespace sw::inbox
