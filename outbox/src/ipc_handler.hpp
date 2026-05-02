#pragma once
#include "store.hpp"
#include <sw/ipc/codec.hpp>
#include <functional>
#include <string>

namespace sw::outbox {

// Callback to trigger an immediate delivery attempt after enqueue.
using EnqueueCb = std::function<void(const std::string& message_id)>;

class IpcHandler {
public:
    IpcHandler(OutboxStore& store, EnqueueCb enqueue_cb)
        : store_(store), enqueue_cb_(std::move(enqueue_cb)) {}

    ipc::CborMap handle(const std::string& method,
                        const ipc::CborMap& params,
                        const std::string&  caller);

private:
    OutboxStore& store_;
    EnqueueCb    enqueue_cb_;

    ipc::CborMap enqueue          (const ipc::CborMap& p);
    ipc::CborMap enqueue_broadcast(const ipc::CborMap& p);
    ipc::CborMap status           (const ipc::CborMap& p);
    ipc::CborMap broadcast_status (const ipc::CborMap& p);
    ipc::CborMap cancel           (const ipc::CborMap& p);
    ipc::CborMap list_pending     (const ipc::CborMap& p);
    ipc::CborMap stats            (const ipc::CborMap& p);
    ipc::CborMap add_sibling      (const ipc::CborMap& p);
    ipc::CborMap remove_sibling   (const ipc::CborMap& p);
    ipc::CborMap update_auth_cert (const ipc::CborMap& p);
};

} // namespace sw::outbox
