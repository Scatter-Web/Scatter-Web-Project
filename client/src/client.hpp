#pragma once
#include "config.hpp"
#include "keystore.hpp"
#include "store.hpp"
#include "ratchet_manager.hpp"
#include "cert.hpp"
#include "dht_pub.hpp"
#include <sw/ipc/client.hpp>
#include <sw/ipc/server.hpp>
#include <atomic>
#include <mutex>
#include <string>
#include <thread>

namespace sw::client {

class IpcHandler;

class Client {
public:
    explicit Client(const Config& cfg);
    ~Client();

    void start();
    void stop();
    void wait();

    // ── UI-facing operations (called by IpcHandler) ───────────────────────────

    // Session
    void        unlock(const std::string& passphrase);
    void        lock();
    bool        is_unlocked() const;
    void        change_passphrase(const std::string& old_p, const std::string& new_p);

    // Identity
    std::string get_display_name();
    std::string get_contact_card_uri();
    void        set_display_name(const std::string& name);

    // Contacts
    std::vector<Contact>   list_contacts();
    std::optional<Contact> get_contact(const std::string& id);
    void                   send_contact_request(const std::string& contact_card_uri);
    void                   accept_contact_request(const std::string& contact_id);
    void                   decline_contact_request(const std::string& contact_id);
    void                   block_contact(const std::string& contact_id);

    // Conversations
    std::vector<Conversation>   list_conversations();
    std::optional<Conversation> get_conversation(const std::string& id);

    // Messages
    std::vector<StoredMessage> get_messages(const std::string& conv_id,
                                             int64_t before_seq, int limit);
    std::string send_message(const std::string& conv_id,
                              const std::string& text,
                              const std::string& reply_to_id = {});
    void        send_reaction(const std::string& msg_id, const std::string& emoji);
    void        send_unreact(const std::string& msg_id, const std::string& emoji);
    void        send_edit(const std::string& msg_id, const std::string& new_text);
    void        send_delete(const std::string& msg_id);
    void        send_typing(const std::string& conv_id, const std::string& action);
    void        mark_read(const std::string& conv_id, const std::string& up_to_id);

    // Groups
    std::string create_group(const std::string& name, const std::string& type);
    void        invite_to_group(const std::string& group_id,
                                 const std::string& contact_id);
    void        kick_from_group(const std::string& group_id,
                                 const std::string& contact_id);
    void        leave_group(const std::string& group_id);

    // Devices
    std::vector<KeyCIssued> list_devices();
    void                    revoke_device(const std::string& device_id);

    // Network/status
    ipc::CborMap get_network_status();
    ipc::CborMap get_inbox_status();
    ipc::CborMap get_outbox_status();

    ipc::Server& ipc_server() { return *ipc_server_; }

    std::string my_sender_id_hex();

private:
    Config            cfg_;
    Keystore          keystore_;
    MessageStore      store_;
    RatchetManager    ratchet_mgr_;
    ipc::Client       ar_client_;
    ipc::Client       inbox_client_;
    ipc::Client       outbox_client_;
    std::unique_ptr<IpcHandler> ipc_handler_;
    std::unique_ptr<ipc::Server> ipc_server_;

    std::atomic<bool> running_{false};
    std::thread       dht_thread_;
    std::thread       cert_renew_thread_;
    mutable std::mutex state_mu_;

    void connect_services();
    void push_sender_allowlist();
    void publish_dht_records(uint64_t timeslot);
    void check_renew_key_c();
    void replenish_prekeys();
    void fetch_pending_messages();

    // Receive flow
    void on_inbox_message(const std::string& message_id);
    void process_delivery_frame(const std::string& message_id,
                                  const Bytes& frame_bytes);
    void dispatch_app_frame(const std::string& conv_id,
                             const std::string& frame_type,
                             const Bytes&       app_frame_bytes,
                             const Bytes&       raw_frame);

    // Outbox delivery status updates
    void on_outbox_status(const std::string& message_id,
                           const std::string& status,
                           int64_t            updated_at);

    // Build and submit a delivery frame to the outbox
    void enqueue_dm(const std::string& conv_id,
                     const std::string& app_frame_type,
                     const Bytes&       app_frame_cbor,
                     const std::string& persistence,
                     const std::string& message_id);

    // DHT loop: publish every 30 minutes
    void dht_loop();
    // Cert renewal loop: check every hour
    void cert_renew_loop();

    // Encode a ratchet envelope around encrypted app_frame bytes
    Bytes encrypt_ratchet_envelope(const std::string& conv_id,
                                    const Bytes& app_frame_cbor);

    // Encode a sender_key envelope around encrypted app_frame bytes
    Bytes encrypt_sender_key_envelope(const std::string& group_id,
                                       const Bytes& app_frame_cbor);

    // Decode and decrypt a ratchet envelope
    Bytes decrypt_ratchet_envelope(const std::string& conv_id,
                                    const Bytes& envelope_bytes);

    // Decode and decrypt a sender_key envelope
    Bytes decrypt_sender_key_envelope(const std::string& group_id,
                                       const std::string& sender_id_hex,
                                       const Bytes& envelope_bytes);

    // Helpers
    KeyA        require_key_a();
    GuardInfo   get_guard_info();
};

} // namespace sw::client
