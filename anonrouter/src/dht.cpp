#include "dht.hpp"
#include <iomanip>
#include <sstream>

namespace sw::anonrouter {

std::string DhtClient::hex(const Key32& k) {
    std::ostringstream ss;
    for (uint8_t b : k) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}

void DhtClient::publish(const Key32& dht_key, Bytes value) {
    std::lock_guard lk(mu_);
    store_[hex(dht_key)] = std::move(value);
}

void DhtClient::lookup(const Key32& dht_key, DhtCallback cb) {
    cb(lookup_sync(dht_key));
}

std::optional<Bytes> DhtClient::lookup_sync(const Key32& dht_key) {
    std::lock_guard lk(mu_);
    auto it = store_.find(hex(dht_key));
    if (it == store_.end()) return std::nullopt;
    return it->second;
}

void DhtClient::remove(const Key32& dht_key) {
    std::lock_guard lk(mu_);
    store_.erase(hex(dht_key));
}

} // namespace sw::anonrouter
