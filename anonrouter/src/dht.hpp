#pragma once
#include <sw/types.hpp>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

// DHT client interface. AnonRouter calls dht.lookup / dht.publish; the actual
// Kademlia routing is handled by cpp-libp2p under the hood.
//
// This stub implementation stores records in memory and resolves them locally.
// In production, replace the internals with a libp2p host's DHT API.

namespace sw::anonrouter {

using DhtCallback = std::function<void(std::optional<Bytes> value)>;

class DhtClient {
public:
    DhtClient() = default;

    // Publish a value under a 32-byte key. Overwrites any existing record.
    void publish(const Key32& dht_key, Bytes value);

    // Look up a value. Calls cb asynchronously (currently synchronously in
    // this stub — replace with network I/O in production).
    void lookup(const Key32& dht_key, DhtCallback cb);

    // Synchronous variant for convenience.
    std::optional<Bytes> lookup_sync(const Key32& dht_key);

    // Remove a local record (e.g. on timeslot rotation).
    void remove(const Key32& dht_key);

private:
    std::mutex mu_;
    std::unordered_map<std::string, Bytes> store_;

    static std::string hex(const Key32& k);
};

} // namespace sw::anonrouter
