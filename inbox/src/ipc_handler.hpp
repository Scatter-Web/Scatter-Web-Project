#pragma once
#include "store.hpp"
#include <sw/ipc/codec.hpp>
#include <functional>
#include <string>

namespace sw::inbox {

// Dispatches IPC calls from the local Client to the correct inbox operation.
// guard_info_cb is called by inbox.guard_info to fetch the current guard state
// from AnonRouter (injected by Inbox to avoid circular dependency).

using GuardInfoCb = std::function<ipc::CborMap()>;

class IpcHandler {
public:
    IpcHandler(InboxStore& store, GuardInfoCb guard_info_cb)
        : store_(store), guard_info_cb_(std::move(guard_info_cb)) {}

    ipc::CborMap handle(const std::string& method,
                        const ipc::CborMap& params,
                        const std::string&  caller);

private:
    InboxStore&  store_;
    GuardInfoCb  guard_info_cb_;

    ipc::CborMap get_pending       (const ipc::CborMap& p);
    ipc::CborMap get_message       (const ipc::CborMap& p);
    ipc::CborMap ack               (const ipc::CborMap& p);
    ipc::CborMap guard_info        (const ipc::CborMap& p);
    ipc::CborMap update_dht_delegation  (const ipc::CborMap& p);
    ipc::CborMap update_contact_outboxes(const ipc::CborMap& p);
    ipc::CborMap update_sender_allowlist(const ipc::CborMap& p);
    ipc::CborMap add_sibling       (const ipc::CborMap& p);
    ipc::CborMap remove_sibling    (const ipc::CborMap& p);
    ipc::CborMap set_retention_days(const ipc::CborMap& p);
    ipc::CborMap status            (const ipc::CborMap& p);
};

} // namespace sw::inbox
