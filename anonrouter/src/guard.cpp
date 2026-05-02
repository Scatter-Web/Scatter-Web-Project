#include "guard.hpp"
#include <sw/crypto/kdf.hpp>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace sw::anonrouter {

std::string GuardTable::key(const SessionToken& t) {
    std::ostringstream ss;
    for (uint8_t b : t) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}

bool GuardTable::add(const GuardEntry& entry) {
    std::lock_guard lk(mu_);
    if (table_.size() >= max_slots_) return false;
    table_[key(entry.session_tok)] = entry;
    return true;
}

void GuardTable::remove(const SessionToken& tok) {
    std::lock_guard lk(mu_);
    table_.erase(key(tok));
}

std::optional<GuardEntry> GuardTable::lookup(const SessionToken& tok) const {
    std::lock_guard lk(mu_);
    auto it = table_.find(key(tok));
    if (it == table_.end()) return std::nullopt;
    return it->second;
}

void GuardTable::add_forwarded(const SessionToken& tok, int64_t n) {
    std::lock_guard lk(mu_);
    auto it = table_.find(key(tok));
    if (it != table_.end()) it->second.bytes_fwd += n;
}

size_t GuardTable::evict_expired(int64_t now_s) {
    std::lock_guard lk(mu_);
    size_t removed = 0;
    for (auto it = table_.begin(); it != table_.end(); ) {
        const auto& e = it->second;
        if (e.ttl_s >= 0 && (now_s - e.created_at_s) > e.ttl_s) {
            it = table_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

size_t GuardTable::size() const {
    std::lock_guard lk(mu_);
    return table_.size();
}

std::vector<GuardEntry> GuardTable::snapshot() const {
    std::lock_guard lk(mu_);
    std::vector<GuardEntry> out;
    out.reserve(table_.size());
    for (auto& [k, v] : table_) out.push_back(v);
    return out;
}

} // namespace sw::anonrouter
