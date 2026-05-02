#pragma once
#include <sw/types.hpp>
#include <sw/crypto/aes_gcm.hpp>
#include <array>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <chrono>

// Guard Routing Table.
//
// When this node acts as a relay/guard for other peers it registers their
// session tokens here. On every incoming cell the router looks up the token
// and forwards the fixed-size cell to the registered destination.

namespace sw::anonrouter {

enum class GuardType : uint8_t {
    INBOUND_PUBLIC  = 0,  // accepts new contact handshakes; 30-min TTL
    INBOUND_PRIVATE = 1,  // active session receive path; per-session TTL
    OUTBOUND        = 2,  // active session send path; per-session TTL
    RENDEZVOUS      = 3,  // bridges two peers at Level 0.5
};

struct GuardEntry {
    SessionToken session_tok   = {};
    std::string  forward_addr;          // "ip:port" we forward cells to
    std::string  recruiter_node_id;     // SHA3-256 hex of recruiter's Key H pubkey
    GuardType    type          = GuardType::INBOUND_PRIVATE;
    int64_t      bytes_fwd     = 0;     // total bytes forwarded (TFT accounting)
    int64_t      created_at_s  = 0;     // unix seconds
    int32_t      ttl_s         = 1800;  // TTL in seconds; -1 = indefinite
};

class GuardTable {
public:
    explicit GuardTable(size_t max_slots) : max_slots_(max_slots) {}

    // Returns false if at capacity.
    bool add(const GuardEntry& entry);

    void remove(const SessionToken& tok);

    std::optional<GuardEntry> lookup(const SessionToken& tok) const;

    // Increment bytes_fwd for an entry; no-op if token not found.
    void add_forwarded(const SessionToken& tok, int64_t n);

    // Remove entries past their TTL. Returns count removed.
    size_t evict_expired(int64_t now_s);

    size_t size() const;
    size_t max_slots() const { return max_slots_; }

    // Snapshot all entries for IPC diagnostics.
    std::vector<GuardEntry> snapshot() const;

private:
    size_t max_slots_;
    mutable std::mutex mu_;
    std::unordered_map<std::string, GuardEntry> table_;  // hex(tok) → entry

    static std::string key(const SessionToken& t);
};

} // namespace sw::anonrouter
