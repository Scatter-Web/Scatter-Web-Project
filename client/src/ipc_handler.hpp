#pragma once
#include <sw/ipc/codec.hpp>
#include <string>

namespace sw::client {

class Client;

class IpcHandler {
public:
    explicit IpcHandler(Client& client);

    ipc::CborMap handle(const std::string& method,
                         const ipc::CborMap& params,
                         const std::string& caller);

private:
    Client& client_;

    ipc::CborMap session_unlock(const ipc::CborMap& p);
    ipc::CborMap session_lock(const ipc::CborMap& p);
    ipc::CborMap session_is_unlocked(const ipc::CborMap& p);
    ipc::CborMap session_change_passphrase(const ipc::CborMap& p);

    ipc::CborMap identity_get_profile(const ipc::CborMap& p);
    ipc::CborMap identity_set_display_name(const ipc::CborMap& p);

    ipc::CborMap contacts_list(const ipc::CborMap& p);
    ipc::CborMap contacts_get(const ipc::CborMap& p);
    ipc::CborMap contacts_send_request(const ipc::CborMap& p);
    ipc::CborMap contacts_accept_request(const ipc::CborMap& p);
    ipc::CborMap contacts_decline_request(const ipc::CborMap& p);
    ipc::CborMap contacts_block(const ipc::CborMap& p);

    ipc::CborMap conversations_list(const ipc::CborMap& p);
    ipc::CborMap conversations_get(const ipc::CborMap& p);

    ipc::CborMap messages_get(const ipc::CborMap& p);
    ipc::CborMap messages_send(const ipc::CborMap& p);
    ipc::CborMap messages_edit(const ipc::CborMap& p);
    ipc::CborMap messages_delete(const ipc::CborMap& p);
    ipc::CborMap messages_react(const ipc::CborMap& p);
    ipc::CborMap messages_unreact(const ipc::CborMap& p);
    ipc::CborMap messages_mark_read(const ipc::CborMap& p);
    ipc::CborMap messages_send_typing(const ipc::CborMap& p);

    ipc::CborMap groups_create(const ipc::CborMap& p);
    ipc::CborMap groups_invite(const ipc::CborMap& p);
    ipc::CborMap groups_kick(const ipc::CborMap& p);
    ipc::CborMap groups_leave(const ipc::CborMap& p);

    ipc::CborMap servers_create_channel(const ipc::CborMap& p);
    ipc::CborMap servers_set_member_role(const ipc::CborMap& p);

    ipc::CborMap devices_list(const ipc::CborMap& p);
    ipc::CborMap devices_revoke(const ipc::CborMap& p);
    ipc::CborMap devices_get_inbox_status(const ipc::CborMap& p);
    ipc::CborMap devices_get_outbox_status(const ipc::CborMap& p);

    ipc::CborMap network_get_status(const ipc::CborMap& p);
};

} // namespace sw::client
