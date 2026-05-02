#pragma once
#include "channel.hpp"
#include "dht.hpp"
#include "guard.hpp"
#include "tft.hpp"
#include <sw/ipc/codec.hpp>
#include <string>

// Maps incoming IPC method calls to the correct subsystem.
// Returns a CborMap result (or throws on error, which the IPC server converts
// to an error response with the exception message).

namespace sw::anonrouter {

class IpcHandler {
public:
    IpcHandler(ChannelManager& channels,
               DhtClient&      dht,
               GuardTable&     guard_table,
               TftEngine&      tft)
        : channels_(channels), dht_(dht),
          guard_table_(guard_table), tft_(tft) {}

    // Main dispatch. Throws std::runtime_error on unknown method or bad params.
    ipc::CborMap handle(const std::string& method,
                        const ipc::CborMap& params,
                        const std::string&  caller);

private:
    ChannelManager& channels_;
    DhtClient&      dht_;
    GuardTable&     guard_table_;
    TftEngine&      tft_;

    ipc::CborMap channel_open(const ipc::CborMap& p);
    ipc::CborMap channel_accept(const ipc::CborMap& p);
    ipc::CborMap channel_reject(const ipc::CborMap& p);
    ipc::CborMap channel_upgrade(const ipc::CborMap& p);
    ipc::CborMap channel_close(const ipc::CborMap& p);
    ipc::CborMap channel_list(const ipc::CborMap& p);
    ipc::CborMap frame_send(const ipc::CborMap& p);
    ipc::CborMap frame_send_batch(const ipc::CborMap& p);
    ipc::CborMap dht_lookup(const ipc::CborMap& p);
    ipc::CborMap dht_publish(const ipc::CborMap& p);
    ipc::CborMap tft_status(const ipc::CborMap& p);

    // Helpers.
    static MessageId require_channel_id(const ipc::CborMap& p);
    static std::string chan_id_hex(const MessageId& id);
    static MessageId from_hex(const std::string& h);
};

} // namespace sw::anonrouter
