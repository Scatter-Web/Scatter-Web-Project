#include "router.hpp"
#include <sw/crypto/kdf.hpp>
#include <cbor.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <ctime>
#include <cstring>

namespace sw::anonrouter {

using namespace std::chrono_literals;

static uint64_t safe_cbor_uint(const cbor_item_t* item) {
    switch (cbor_int_get_width(item)) {
        case CBOR_INT_8:  return cbor_get_uint8(item);
        case CBOR_INT_16: return cbor_get_uint16(item);
        case CBOR_INT_32: return cbor_get_uint32(item);
        case CBOR_INT_64: return cbor_get_uint64(item);
    }
    return 0;
}

static std::string chan_id_hex(const MessageId& id) {
    std::ostringstream ss;
    for (uint8_t b : id) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}

static MessageId chan_id_from_hex(const std::string& h) {
    MessageId id{};
    if (h.size() < 32) return id;
    for (size_t i = 0; i < 16; ++i)
        id[i] = static_cast<uint8_t>(std::stoi(h.substr(i * 2, 2), nullptr, 16));
    return id;
}

// ─ Zero key used for handshake cells (CHAN_OPEN / CHAN_ACCEPT). ───────────────
// These cells are not secret — they carry only the channel_id + channel_key
// from acceptor to initiator, after which the real per-channel key takes over.
static crypto::AesKey handshake_key() {
    crypto::AesKey k{};
    return k;  // all zeros
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
                      return dispatch_ipc(method, params, caller);
                  })
{
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

// ── IPC dispatch (intercepts handshake methods) ───────────────────────────────

ipc::CborMap Router::dispatch_ipc(const std::string& method,
                                    const ipc::CborMap& params,
                                    const std::string& caller) {
    if (method == "channel.open") {
        // Let the handler create the channel record first.
        auto result = ipc_handler_.handle(method, params, caller);

        // If peer_addr was given, fire the CHAN_OPEN cell immediately.
        auto pa_it = params.find("peer_addr");
        auto id_it = result.find("channel_id");
        if (pa_it != params.end() && pa_it->second.is_string() &&
            id_it != result.end() && id_it->second.is_string()) {
            std::string peer_addr = pa_it->second.as_string();
            MessageId   chan_id   = chan_id_from_hex(id_it->second.as_string());

            // Determine anon_level and mode from params.
            uint64_t    anon_raw  = 0;
            std::string mode_str  = "message";
            {
                auto it = params.find("anon_level");
                if (it != params.end() && it->second.is_uint())
                    anon_raw = it->second.as_uint();
            }
            {
                auto it = params.find("mode");
                if (it != params.end() && it->second.is_string())
                    mode_str = it->second.as_string();
            }
            AnonLevel anon = static_cast<AnonLevel>(
                anon_raw > 2 ? 2 : static_cast<uint8_t>(anon_raw));
            ChannelMode mode = (mode_str == "stream")   ? ChannelMode::STREAM
                             : (mode_str == "datagram") ? ChannelMode::DATAGRAM
                                                        : ChannelMode::MESSAGE;
            send_chan_open(chan_id, anon, mode, peer_addr);
        }
        return result;
    }

    if (method == "channel.accept") {
        auto id_it = params.find("channel_id");
        if (id_it == params.end() || !id_it->second.is_string())
            return ipc_handler_.handle(method, params, caller);

        MessageId chan_id = chan_id_from_hex(id_it->second.as_string());
        crypto::AesKey channel_key{};
        bool ok = channels_.accept(chan_id, channel_key);

        // Send CHAN_ACCEPT directly to the peer if this is a direct channel.
        auto ci = channels_.get(chan_id);
        if (ci && !ci->peer_addr.empty())
            send_chan_accept(chan_id, channel_key, ci->peer_addr);

        std::cout << "[anonrouter] channel.accept chan_id=" << chan_id_hex(chan_id)
                  << " state=open key_sent=" << ok << "\n";

        // Return response directly — do NOT call ipc_handler_.handle() to avoid
        // a second channels_.accept() that would overwrite the channel key.
        return ipc::CborMap{
            {"channel_id", ipc::CborValue::from_string(chan_id_hex(chan_id))},
            {"ok",         ipc::CborValue::from_bool(ok)},
        };
    }

    return ipc_handler_.handle(method, params, caller);
}

// ── Datagram handler ──────────────────────────────────────────────────────────

void Router::on_datagram(const std::string& peer_addr, Bytes data) {
    if (data.size() != CELL_SIZE) return;

    Cell cell{};
    std::copy(data.begin(), data.end(), cell.begin());

    CellType cell_type = static_cast<CellType>(cell[1]);

    if (cell_type == CellType::CHAN_OPEN) {
        on_chan_open_cell(peer_addr, cell);
        return;
    }
    if (cell_type == CellType::CHAN_ACCEPT) {
        on_chan_accept_cell(cell);
        return;
    }

    SessionToken tok = cell_session_tok(cell);
    auto entry = guard_table_.lookup(tok);

    if (entry) {
        relay_cell(cell);
    } else {
        tunnels_.on_inbound_cell(cell, [this](const SessionToken& /*tok*/, Cell c) {
            channels_.on_cell(c);
        });
    }
}

// ── CHAN_OPEN cell received ───────────────────────────────────────────────────

void Router::on_chan_open_cell(const std::string& peer_addr, const Cell& cell) {
    // Decrypt using the zero handshake key.
    Bytes payload;
    try {
        auto dc = cell_decode(cell, handshake_key());
        payload.assign(dc.garlic_data.begin(),
                       dc.garlic_data.begin() + dc.header.garlic_len);
    } catch (...) {
        std::cerr << "[anonrouter] CHAN_OPEN decrypt failed from " << peer_addr << "\n";
        return;
    }

    // Parse CBOR: {channel_id: bstr16, anon_level: uint, mode: uint}
    struct cbor_load_result res{};
    cbor_item_t* root = cbor_load(payload.data(), payload.size(), &res);
    if (!root || res.error.code != CBOR_ERR_NONE || !cbor_isa_map(root)) {
        if (root) cbor_decref(&root);
        std::cerr << "[anonrouter] CHAN_OPEN bad CBOR from " << peer_addr << "\n";
        return;
    }

    MessageId   channel_id{};
    AnonLevel   anon_level = AnonLevel::DIRECT;
    ChannelMode mode       = ChannelMode::MESSAGE;

    for (size_t i = 0; i < cbor_map_size(root); ++i) {
        auto pair = cbor_map_handle(root)[i];
        std::string k(reinterpret_cast<char*>(cbor_string_handle(pair.key)),
                      cbor_string_length(pair.key));
        if (k == "channel_id" && cbor_isa_bytestring(pair.value)
                && cbor_bytestring_length(pair.value) == 16)
            std::memcpy(channel_id.data(), cbor_bytestring_handle(pair.value), 16);
        else if (k == "anon_level" && cbor_isa_uint(pair.value))
            anon_level = static_cast<AnonLevel>(safe_cbor_uint(pair.value));
        else if (k == "mode" && cbor_isa_uint(pair.value))
            mode = static_cast<ChannelMode>(safe_cbor_uint(pair.value));
    }
    cbor_decref(&root);

    channels_.register_incoming(channel_id, peer_addr, anon_level, mode);

    std::cout << "[anonrouter] CHAN_OPEN received chan_id=" << chan_id_hex(channel_id)
              << " from=" << peer_addr << "\n";
}

// ── CHAN_ACCEPT cell received ─────────────────────────────────────────────────

void Router::on_chan_accept_cell(const Cell& cell) {
    Bytes payload;
    try {
        auto dc = cell_decode(cell, handshake_key());
        payload.assign(dc.garlic_data.begin(),
                       dc.garlic_data.begin() + dc.header.garlic_len);
    } catch (...) {
        std::cerr << "[anonrouter] CHAN_ACCEPT decrypt failed\n";
        return;
    }

    // Parse CBOR: {channel_id: bstr16, channel_key: bstr32}
    struct cbor_load_result res{};
    cbor_item_t* root = cbor_load(payload.data(), payload.size(), &res);
    if (!root || res.error.code != CBOR_ERR_NONE || !cbor_isa_map(root)) {
        if (root) cbor_decref(&root);
        std::cerr << "[anonrouter] CHAN_ACCEPT bad CBOR\n";
        return;
    }

    MessageId      channel_id{};
    crypto::AesKey channel_key{};
    bool           got_key = false;

    for (size_t i = 0; i < cbor_map_size(root); ++i) {
        auto pair = cbor_map_handle(root)[i];
        std::string k(reinterpret_cast<char*>(cbor_string_handle(pair.key)),
                      cbor_string_length(pair.key));
        if (k == "channel_id" && cbor_isa_bytestring(pair.value)
                && cbor_bytestring_length(pair.value) == 16)
            std::memcpy(channel_id.data(), cbor_bytestring_handle(pair.value), 16);
        else if (k == "channel_key" && cbor_isa_bytestring(pair.value)
                && cbor_bytestring_length(pair.value) == 32) {
            std::memcpy(channel_key.data(), cbor_bytestring_handle(pair.value), 32);
            got_key = true;
        }
    }
    cbor_decref(&root);

    if (!got_key) {
        std::cerr << "[anonrouter] CHAN_ACCEPT missing channel_key\n";
        return;
    }

    // Install the key from the acceptor and mark channel OPEN.
    channels_.on_chan_accept(payload);

    std::cout << "[anonrouter] CHAN_ACCEPT received chan_id=" << chan_id_hex(channel_id)
              << " channel=open\n";
}

// ── Build and send handshake cells ───────────────────────────────────────────

void Router::send_chan_open(const MessageId& channel_id, AnonLevel anon, ChannelMode mode,
                             const std::string& peer_addr) {
    // Build CBOR payload: {channel_id: bstr16, anon_level: uint, mode: uint}
    cbor_item_t* m = cbor_new_definite_map(3);
    cbor_map_add(m, {cbor_build_string("channel_id"),
                     cbor_build_bytestring(channel_id.data(), channel_id.size())});
    cbor_map_add(m, {cbor_build_string("anon_level"),
                     cbor_build_uint64(static_cast<uint8_t>(anon))});
    cbor_map_add(m, {cbor_build_string("mode"),
                     cbor_build_uint64(static_cast<uint8_t>(mode))});
    uint8_t* buf = nullptr; size_t buf_len = 0;
    cbor_serialize_alloc(m, &buf, &buf_len);
    cbor_decref(&m);
    if (!buf || buf_len > CELL_PLAINTEXT_SIZE) { free(buf); return; }

    CellHeader hdr;
    hdr.cell_type  = CellType::CHAN_OPEN;
    hdr.garlic_len = static_cast<uint16_t>(buf_len);
    Cell cell = cell_build(hdr, handshake_key(), ByteSpan{buf, buf_len});
    free(buf);

    transport_.send(peer_addr, ByteSpan{cell.data(), cell.size()});

    std::cout << "[anonrouter] CHAN_OPEN sent chan_id=" << chan_id_hex(channel_id)
              << " to=" << peer_addr << "\n";
}

void Router::send_chan_accept(const MessageId& channel_id,
                               const crypto::AesKey& channel_key,
                               const std::string& peer_addr) {
    // Build CBOR payload: {channel_id: bstr16, channel_key: bstr32}
    cbor_item_t* m = cbor_new_definite_map(2);
    cbor_map_add(m, {cbor_build_string("channel_id"),
                     cbor_build_bytestring(channel_id.data(), channel_id.size())});
    cbor_map_add(m, {cbor_build_string("channel_key"),
                     cbor_build_bytestring(channel_key.data(), channel_key.size())});
    uint8_t* buf = nullptr; size_t buf_len = 0;
    cbor_serialize_alloc(m, &buf, &buf_len);
    cbor_decref(&m);
    if (!buf || buf_len > CELL_PLAINTEXT_SIZE) { free(buf); return; }

    CellHeader hdr;
    hdr.cell_type  = CellType::CHAN_ACCEPT;
    hdr.garlic_len = static_cast<uint16_t>(buf_len);
    Cell cell = cell_build(hdr, handshake_key(), ByteSpan{buf, buf_len});
    free(buf);

    transport_.send(peer_addr, ByteSpan{cell.data(), cell.size()});

    std::cout << "[anonrouter] CHAN_ACCEPT sent chan_id=" << chan_id_hex(channel_id)
              << " to=" << peer_addr << "\n";
}

// ── Relay ─────────────────────────────────────────────────────────────────────

void Router::relay_cell(const Cell& cell) {
    SessionToken tok = cell_session_tok(cell);
    auto entry = guard_table_.lookup(tok);
    if (!entry) return;

    transport_.send(entry->forward_addr, ByteSpan{cell.data(), cell.size()});
    guard_table_.add_forwarded(tok, static_cast<int64_t>(CELL_SIZE));

    if (!entry->recruiter_node_id.empty())
        tft_.record_forwarded_for(entry->recruiter_node_id,
                                   static_cast<int64_t>(CELL_SIZE));
}

// ── Periodic loops ────────────────────────────────────────────────────────────

void Router::tft_loop() {
    auto round_s  = std::chrono::seconds(cfg_.tft.round_seconds);
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
        {"peer_addr",     ipc::CborValue::from_string(ci.peer_addr)},
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
