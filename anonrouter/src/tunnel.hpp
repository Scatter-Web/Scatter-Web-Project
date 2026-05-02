#pragma once
#include "cell.hpp"
#include "guard.hpp"
#include "tft.hpp"
#include "transport.hpp"
#include <sw/crypto/aes_gcm.hpp>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

// Tunnel management: recruitment of inbound and outbound guards, and the
// per-hop link-encryption layer (Key I: ML-KEM-768 + AES-256-GCM).
//
// Single-hop design: each tunnel has exactly one guard node.

namespace sw::anonrouter {

enum class TunnelType { INBOUND_PUBLIC, INBOUND_PRIVATE, OUTBOUND };

struct TunnelInfo {
    SessionToken       session_tok;
    std::string        guard_endpoint;   // "ip:port"
    std::string        guard_node_id;    // hex SHA3-256 of guard's Key H pub
    crypto::AesKey     link_key;         // Key I: AES-256-GCM per-hop key
    TunnelType         type;
    int64_t            created_at_s = 0;
    // For OUTBOUND tunnels, the address the guard forwards cells to.
    std::string        forward_to;
};

// Recruitment result delivered asynchronously via callback.
struct RecruitResult {
    bool        ok          = false;
    std::string session_tok_hex;
    std::string reason;       // "guard_capacity_full" | "bandwidth_credit_insufficient"
    int64_t     retry_after  = 0;
};

using RecruitCallback = std::function<void(RecruitResult)>;

// Builds the CBOR recruitment request payload (garlic clove payload).
// Used by the router to send RECRUIT_IN / RECRUIT_OUT cells.
Bytes build_recruit_in_payload(const SessionToken& session_tok,
                               const std::string&  deliver_to,
                               GuardType           guard_type,
                               uint32_t            ttl_seconds);

Bytes build_recruit_out_payload(const SessionToken& session_tok,
                                const std::string&  forward_to,
                                uint32_t            ttl_seconds);

// Parse a RECRUIT_OK / RECRUIT_FULL / RECRUIT_CHOKED cell payload.
RecruitResult parse_recruit_response(const Bytes& payload);

// Build a RECRUIT_OK response payload.
Bytes build_recruit_ok(const SessionToken& session_tok);
Bytes build_recruit_full(const SessionToken& session_tok);
Bytes build_recruit_choked(const SessionToken& session_tok, int64_t retry_after_unix);

// ── TunnelManager ────────────────────────────────────────────────────────────

class TunnelManager {
public:
    explicit TunnelManager(GuardTable& guard_table, TftEngine& tft,
                           Transport& transport)
        : guard_table_(guard_table), tft_(tft), transport_(transport) {}

    // Register a newly recruited inbound tunnel.
    void add_inbound(const TunnelInfo& info);

    // Register a newly recruited outbound tunnel.
    void add_outbound(const TunnelInfo& info);

    void remove(const SessionToken& tok);

    std::optional<TunnelInfo> lookup(const SessionToken& tok) const;

    // Forward a raw cell through an outbound tunnel (encrypts with link key).
    void forward_via_outbound(const SessionToken& out_tok, const Cell& cell);

    // Process a cell that just arrived on an inbound tunnel (decrypt link layer,
    // deliver to local channel consumer via cb).
    using InboundCb = std::function<void(const SessionToken& tok, Cell cell)>;
    void on_inbound_cell(const Cell& cell, InboundCb cb);

private:
    GuardTable& guard_table_;
    TftEngine&  tft_;
    Transport&  transport_;

    mutable std::mutex                                mu_;
    std::unordered_map<std::string, TunnelInfo> tunnels_;  // hex(tok) → info

    static std::string tok_key(const SessionToken& t);
};

} // namespace sw::anonrouter
