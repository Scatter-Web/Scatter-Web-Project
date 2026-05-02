#include "tft.hpp"
#include <algorithm>
#include <cmath>

namespace sw::anonrouter {

void TftEngine::record_forwarded_for(const std::string& peer_id, int64_t bytes) {
    std::lock_guard lk(mu_);
    if (!ledger_.count(peer_id)) ledger_[peer_id] = cfg_.new_peer_balance;
    ledger_[peer_id] += bytes;
}

void TftEngine::record_used_from(const std::string& peer_id, int64_t bytes) {
    std::lock_guard lk(mu_);
    if (!ledger_.count(peer_id)) ledger_[peer_id] = cfg_.new_peer_balance;
    ledger_[peer_id] -= bytes;
}

bool TftEngine::is_unchoked(const std::string& peer_id) const {
    std::lock_guard lk(mu_);
    return unchoked_.count(peer_id) || peer_id == opt_unchoked_;
}

bool TftEngine::is_choked_permanent(const std::string& peer_id) const {
    std::lock_guard lk(mu_);
    auto it = ledger_.find(peer_id);
    if (it == ledger_.end()) return false;
    return it->second > cfg_.max_debt_bytes;
}

void TftEngine::run_round() {
    std::lock_guard lk(mu_);
    ++round_number_;

    // Collect non-permanently-choked peers sorted ascending by credits.
    std::vector<std::pair<int64_t, std::string>> candidates;
    candidates.reserve(ledger_.size());
    for (auto& [pid, cred] : ledger_) {
        if (cred <= cfg_.max_debt_bytes)
            candidates.emplace_back(cred, pid);
    }
    std::sort(candidates.begin(), candidates.end());  // ascending = most indebted first

    unchoked_.clear();
    size_t slots = std::min(cfg_.unchoke_slots, candidates.size());
    for (size_t i = 0; i < slots; ++i)
        unchoked_.insert(candidates[i].second);

    // Rotate optimistic unchoke slot every opt_unchoke_interval rounds.
    if (--opt_rounds_left_ <= 0) {
        opt_unchoked_ = pick_opt_unchoke();
        opt_rounds_left_ = cfg_.opt_unchoke_interval;
    }
}

void TftEngine::decay_credits() {
    std::lock_guard lk(mu_);
    for (auto it = ledger_.begin(); it != ledger_.end(); ) {
        it->second = static_cast<int64_t>(it->second * cfg_.credit_decay_factor);
        if (std::abs(it->second) < cfg_.credit_prune_min_bytes)
            it = ledger_.erase(it);
        else
            ++it;
    }
}

TftState TftEngine::state() const {
    std::lock_guard lk(mu_);
    TftState s;
    s.round_number = round_number_;
    s.unchoked_count = unchoked_.size();
    for (auto& p : unchoked_) s.unchoked_peers.push_back(p);
    s.opt_unchoked_peer = opt_unchoked_;

    // Top-5 by absolute credit value for diagnostics.
    std::vector<std::pair<int64_t, std::string>> all;
    all.reserve(ledger_.size());
    for (auto& [pid, c] : ledger_) all.emplace_back(c, pid);
    std::sort(all.begin(), all.end());
    size_t n = std::min<size_t>(5, all.size());
    for (size_t i = 0; i < n; ++i)
        s.top_peers.push_back({all[i].second, all[i].first});
    return s;
}

int64_t TftEngine::credits(const std::string& peer_id) const {
    std::lock_guard lk(mu_);
    auto it = ledger_.find(peer_id);
    return it == ledger_.end() ? 0 : it->second;
}

std::string TftEngine::pick_opt_unchoke() {
    // Pick a random peer currently outside the unchoked set.
    for (auto& [pid, _] : ledger_) {
        if (!unchoked_.count(pid) && pid != opt_unchoked_)
            return pid;
    }
    return {};
}

} // namespace sw::anonrouter
