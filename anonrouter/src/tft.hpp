#pragma once
#include <sw/types.hpp>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Tit-for-Tat bandwidth fairness engine.
//
// Maintains a local-only credit ledger keyed by peer ID (hex string of
// SHA3-256(Key_H_pubkey)). Credits are never shared with peers.
//
//   credits[peer] = bytes_we_forwarded_for_them - bytes_they_forwarded_for_us
//
// A positive balance means we have provided more than we received — the peer
// owes us. Negative means we are indebted.
// Unchoke candidates are sorted ascending (lowest first = most indebted = highest priority).

namespace sw::anonrouter {

struct TftConfig {
    uint32_t round_seconds            = 30;
    size_t   unchoke_slots            = 19;     // regular unchoked peers per round
    int64_t  max_debt_bytes           = 52'428'800;  // 50 MiB ceiling
    int64_t  new_peer_balance         = -10'485'760; // -10 MiB bootstrap debt
    int32_t  opt_unchoke_interval     = 3;           // rounds before rotating opt slot
    int64_t  credit_decay_interval_s  = 3600;
    double   credit_decay_factor      = 0.99;
    int64_t  credit_prune_min_bytes   = 1024;
};

struct TftState {
    std::vector<std::string> unchoked_peers;
    std::string              opt_unchoked_peer;
    size_t                   unchoked_count    = 0;
    int64_t                  round_number      = 0;
    // snapshot of top-5 peers for diagnostics
    struct PeerEntry { std::string peer_id; int64_t credits; };
    std::vector<PeerEntry>   top_peers;
};

class TftEngine {
public:
    explicit TftEngine(TftConfig cfg = {}) : cfg_(cfg) {}

    // Called when we forward N bytes as relay for peer.
    void record_forwarded_for(const std::string& peer_id, int64_t bytes);

    // Called when peer forwards N bytes as relay for us.
    void record_used_from(const std::string& peer_id, int64_t bytes);

    // Returns true if peer is in the current unchoked set.
    bool is_unchoked(const std::string& peer_id) const;

    // Permanently choked if over max_debt ceiling.
    bool is_choked_permanent(const std::string& peer_id) const;

    // Run a TFT round: re-sort and pick unchoked set. Call every round_seconds.
    void run_round();

    // Apply credit decay. Call every credit_decay_interval_s.
    void decay_credits();

    TftState state() const;
    int64_t  credits(const std::string& peer_id) const;

private:
    TftConfig cfg_;
    mutable std::mutex mu_;

    std::unordered_map<std::string, int64_t> ledger_;
    std::unordered_set<std::string>          unchoked_;
    std::string                              opt_unchoked_;
    int64_t                                  round_number_    = 0;
    int32_t                                  opt_rounds_left_ = 0;

    // Picks the next peer for the optimistic unchoke slot from those currently choked.
    std::string pick_opt_unchoke();
};

} // namespace sw::anonrouter
