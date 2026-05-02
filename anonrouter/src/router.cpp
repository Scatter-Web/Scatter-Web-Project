#include "router.hpp"
#include <sw/crypto/kdf.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <ctime>

namespace sw::anonrouter {

using namespace std::chrono_literals;

static std::string chan_id_hex(const MessageId& id) {
    std::ostringstream ss;
    for (uint8_t b : id) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}

Router::Router(Config cfg)
    : cfg_(std::move(cfg))
    , guard_table_(cfg_.tft.max_guard_slots)
    , tft_(TftConfig{
          cfg_.tft.round_seconds,
          cfg_.tft.unchoke_slots,
          cfg_.tft.max_debt_bytes,
          cfg_.tft.new_peer_balance,
          cfg_.tft.opt_unchoke_interval,
          cfg_.tft.credit_decay_interval_s,
          cfg_.tft.credit_decay_factor,
          cfg_.tft.credit_prune_min_bytes,
      })
    , tunnels_(guard_table_, tft_, transport_)
    , channels_(tunnels_, transport_)
    , ipc_handler_(channels_, dht_, guard_table_, tft_)
    , ipc_server_(cfg_.ipc_path,
                  [this](const std::string& method,
                         const ipc::CborMap& params,
                         const std::string& caller) {
                      return ipc_handler_.handle(method, params, caller);
                  })
{
    // Wire channel events to IPC push.
    channels_.set_state_cb([this](const MessageId& id, ChannelState s) {
        if (s == ChannelState::OPENING) {
            auto ci = channels_.get(id);
            if (ci) push_channel_incoming(*ci);
        }
    });
    channels_.set_frame_cb([this](const MessageId& id, Bytes frame) {
        push_frame_recv(id, frame);
    });
}

void Router::start() {
    if (running_.exchange(true)) return;

    transport_.start(cfg_.listen_addr, [this](const std::string& peer, Bytes data) {
        on_datagram(peer, std::move(data));
    });

    ipc_server_.start();

    tft_thread_   = std::thread([this] { tft_loop(); });
    evict_thread_ = std::thread([this] { evict_loop(); });

    std::cout << "[anonrouter] listening on " << cfg_.listen_addr
              << " ipc=" << cfg_.ipc_path << "\n";
}

void Router::stop() {
    if (!running_.exchange(false)) return;
    transport_.stop();
    ipc_server_.stop();
    if (tft_thread_.joinable())   tft_thread_.join();
    if (evict_thread_.joinable()) evict_thread_.join();
}

void Router::wait() {
    while (running_)
        std::this_thread::sleep_for(500ms);
}

// ── Datagram handler ──────────────────────────────────────────────────────────

void Router::on_datagram(const std::string& /*peer_addr*/, Bytes data) {
    if (data.size() != CELL_SIZE) return;  // only fixed-size cells

    Cell cell{};
    std::copy(data.begin(), data.end(), cell.begin());

    SessionToken tok = cell_session_tok(cell);
    auto entry = guard_table_.lookup(tok);

    if (entry) {
        // We are acting as a relay/guard for this token.
        relay_cell(cell);
    } else {
        // Check if this is an inbound tunnel we own (deliver to channel layer).
        tunnels_.on_inbound_cell(cell, [this](const SessionToken& /*tok*/, Cell c) {
            channels_.on_cell(c);
        });
    }
}

void Router::relay_cell(const Cell& cell) {
    SessionToken tok = cell_session_tok(cell);
    auto entry = guard_table_.lookup(tok);
    if (!entry) return;

    transport_.send(entry->forward_addr,
                    ByteSpan{cell.data(), cell.size()});
    guard_table_.add_forwarded(tok, static_cast<int64_t>(CELL_SIZE));

    // TFT accounting: charge the recruiter for our forwarding work.
    if (!entry->recruiter_node_id.empty())
        tft_.record_forwarded_for(entry->recruiter_node_id,
                                   static_cast<int64_t>(CELL_SIZE));
}

// ── Periodic loops ────────────────────────────────────────────────────────────

void Router::tft_loop() {
    auto round_s  = std::chrono::seconds(cfg_.tft.round_seconds);
    auto decay_s  = std::chrono::seconds(cfg_.tft.credit_decay_interval_s);
    int64_t rounds_per_decay = cfg_.tft.credit_decay_interval_s / cfg_.tft.round_seconds;
    int64_t round_count = 0;

    while (running_) {
        std::this_thread::sleep_for(round_s);
        if (!running_) break;
        tft_.run_round();
        if (++round_count % rounds_per_decay == 0)
            tft_.decay_credits();
    }
}

void Router::evict_loop() {
    while (running_) {
        std::this_thread::sleep_for(60s);
        if (!running_) break;
        int64_t now = static_cast<int64_t>(
            std::chrono::system_clock::now().time_since_epoch() /
            std::chrono::seconds(1));
        size_t removed = guard_table_.evict_expired(now);
        if (removed > 0)
            std::cout << "[anonrouter] evicted " << removed << " expired guard slots\n";
    }
}

// ── IPC push helpers ──────────────────────────────────────────────────────────

void Router::push_channel_incoming(const ChannelInfo& ci) {
    ipc::CborMap payload{
        {"channel_id",    ipc::CborValue::from_string(chan_id_hex(ci.channel_id))},
        {"remote_pubkey", ipc::CborValue::from_string(ci.remote_pubkey_hex)},
        {"anon_level",    ipc::CborValue::from_uint(static_cast<uint8_t>(ci.anon_level))},
        {"mode",          ipc::CborValue::from_string(
                              ci.mode == ChannelMode::STREAM   ? "stream"
                            : ci.mode == ChannelMode::DATAGRAM ? "datagram"
                                                               : "message")},
    };
    ipc_server_.push("channel.incoming", payload);
}

void Router::push_frame_recv(const MessageId& channel_id, const Bytes& frame) {
    ipc::CborMap payload{
        {"channel_id", ipc::CborValue::from_string(chan_id_hex(channel_id))},
        {"payload",    ipc::CborValue::from_bytes(frame)},
    };
    ipc_server_.push("frame.recv", payload);
}

} // namespace sw::anonrouter
