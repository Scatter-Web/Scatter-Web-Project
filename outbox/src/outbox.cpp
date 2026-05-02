#include "outbox.hpp"
#include <sw/crypto/kdf.hpp>
#include <cbor.h>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <cstring>

namespace sw::outbox {

using namespace std::chrono_literals;
using namespace sw::ipc;

static int64_t now_ms() {
    return static_cast<int64_t>(
        std::chrono::system_clock::now().time_since_epoch() /
        std::chrono::milliseconds(1));
}

static std::string bytes_to_hex(const Bytes& b) {
    std::ostringstream ss;
    for (uint8_t c : b) ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return ss.str();
}

// ── Construction ──────────────────────────────────────────────────────────────

Outbox::Outbox(Config cfg)
    : cfg_(std::move(cfg))
    , store_(cfg_.db_path)
    , ar_client_(cfg_.anonrouter_path)
    , ipc_handler_(store_, [this](const std::string& id) { immediate_attempt(id); })
    , ipc_server_(cfg_.ipc_path,
                  [this](const std::string& method,
                         const CborMap& params,
                         const std::string& caller) {
                      return ipc_handler_.handle(method, params, caller);
                  })
{}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

void Outbox::start() {
    if (running_.exchange(true)) return;

    ar_client_.on_push([this](const std::string& ev, const CborMap& pl) {
        on_ar_push(ev, pl);
    });
    ar_client_.connect();
    ipc_server_.start();

    startup_burst();

    retry_thread_       = std::thread([this] { retry_loop(); });
    maintenance_thread_ = std::thread([this] { maintenance_loop(); });

    std::cout << "[outbox] started ipc=" << cfg_.ipc_path << "\n";
}

void Outbox::stop() {
    if (!running_.exchange(false)) return;
    ar_client_.disconnect();
    ipc_server_.stop();
    if (retry_thread_.joinable())       retry_thread_.join();
    if (maintenance_thread_.joinable()) maintenance_thread_.join();
}

void Outbox::wait() {
    while (running_) std::this_thread::sleep_for(500ms);
}

// ── AnonRouter push events ────────────────────────────────────────────────────

void Outbox::on_ar_push(const std::string& event, const CborMap& payload) {
    if (event != "frame.recv") return;
    auto ci = payload.find("channel_id");
    auto pi = payload.find("payload");
    if (ci == payload.end() || pi == payload.end()) return;
    if (!ci->second.is_string() || !pi->second.is_bytes()) return;
    on_frame(ci->second.as_string(), pi->second.as_bytes());
}

void Outbox::on_frame(const std::string& channel_id, const Bytes& body) {
    // Detect frame type.
    struct cbor_load_result res{};
    cbor_item_t* root = cbor_load(body.data(), body.size(), &res);
    if (!root || res.error.code != CBOR_ERR_NONE) { if (root) cbor_decref(&root); return; }
    std::string frame_type;
    if (cbor_isa_map(root)) {
        for (size_t i = 0; i < cbor_map_size(root); ++i) {
            auto p = cbor_map_handle(root)[i];
            if (!cbor_isa_string(p.key)) continue;
            std::string k(reinterpret_cast<char*>(cbor_string_handle(p.key)),
                          cbor_string_length(p.key));
            if (k == "type" && cbor_isa_string(p.value)) {
                frame_type.assign(
                    reinterpret_cast<char*>(cbor_string_handle(p.value)),
                    cbor_string_length(p.value));
                break;
            }
        }
    }
    cbor_decref(&root);

    if (frame_type == "delivery_ack")    handle_delivery_ack(channel_id, body);
    else if (frame_type == "outbox_poll") {
        // An Inbox is polling us. Respond with pending messages for that inbox.
        // Parse inbox_key_c_pubkey from poll body.
        struct cbor_load_result r2{};
        cbor_item_t* poll = cbor_load(body.data(), body.size(), &r2);
        if (!poll || r2.error.code != CBOR_ERR_NONE) { if (poll) cbor_decref(&poll); return; }

        Bytes inbox_key_c_pub;
        for (size_t i = 0; i < cbor_map_size(poll); ++i) {
            auto p = cbor_map_handle(poll)[i];
            if (!cbor_isa_string(p.key)) continue;
            std::string k(reinterpret_cast<char*>(cbor_string_handle(p.key)),
                          cbor_string_length(p.key));
            if (k == "inbox_key_c_pubkey" && cbor_isa_bytestring(p.value)) {
                auto* h = cbor_bytestring_handle(p.value);
                inbox_key_c_pub.assign(h, h + cbor_bytestring_length(p.value));
            }
        }
        cbor_decref(&poll);
        if (inbox_key_c_pub.empty()) return;

        // Collect all pending messages this Inbox is a recipient for.
        auto pending = store_.list_pending();
        std::vector<std::pair<std::string,Bytes>> msgs_for_inbox;
        for (auto& m : pending) {
            if (store_.is_valid_recipient_inbox(m.message_id, inbox_key_c_pub))
                msgs_for_inbox.push_back({m.message_id, m.delivery_frame});
        }

        // Build and send outbox_poll_response.
        cbor_item_t* resp = cbor_new_definite_map(2);
        cbor_map_add(resp, {cbor_build_string("type"),
                            cbor_build_string("outbox_poll_response")});
        cbor_item_t* arr = cbor_new_definite_array(msgs_for_inbox.size());
        for (auto& [mid, frame] : msgs_for_inbox) {
            cbor_item_t* e = cbor_new_definite_map(2);
            cbor_map_add(e, {cbor_build_string("message_id"),
                             cbor_build_string(mid.c_str())});
            cbor_map_add(e, {cbor_build_string("delivery_frame"),
                             cbor_build_bytestring(frame.data(), frame.size())});
            cbor_array_push(arr, e);
        }
        cbor_map_add(resp, {cbor_build_string("messages"), arr});

        uint8_t* buf = nullptr; size_t len = 0;
        cbor_serialize_alloc(resp, &buf, &len);
        cbor_decref(&resp);
        if (!buf) return;
        Bytes payload(buf, buf + len);
        free(buf);

        try {
            ar_client_.call("frame.send", {
                {"channel_id", CborValue::from_string(channel_id)},
                {"payload",    CborValue::from_bytes(payload)},
            });
        } catch (...) {}
    }
    else if (frame_type == "outbox_poll_ack") handle_poll_ack(body);
    else if (frame_type == "outbox_replication_ack") {} // sibling ack; nothing to do
}

// ── Delivery ACK handler ──────────────────────────────────────────────────────

void Outbox::handle_delivery_ack(const std::string& /*channel_id*/, const Bytes& body) {
    struct cbor_load_result res{};
    cbor_item_t* root = cbor_load(body.data(), body.size(), &res);
    if (!root || res.error.code != CBOR_ERR_NONE) { if (root) cbor_decref(&root); return; }

    std::string message_id;
    Bytes       inbox_key_c_pub;
    for (size_t i = 0; i < cbor_map_size(root); ++i) {
        auto p = cbor_map_handle(root)[i];
        if (!cbor_isa_string(p.key)) continue;
        std::string k(reinterpret_cast<char*>(cbor_string_handle(p.key)),
                      cbor_string_length(p.key));
        if (k == "message_id" && cbor_isa_string(p.value))
            message_id.assign(
                reinterpret_cast<char*>(cbor_string_handle(p.value)),
                cbor_string_length(p.value));
        else if (k == "inbox_key_c_pubkey" && cbor_isa_bytestring(p.value)) {
            auto* h = cbor_bytestring_handle(p.value);
            inbox_key_c_pub.assign(h, h + cbor_bytestring_length(p.value));
        }
    }
    cbor_decref(&root);

    if (message_id.empty() || inbox_key_c_pub.empty()) return;
    if (!store_.is_valid_recipient_inbox(message_id, inbox_key_c_pub)) return;

    store_.set_status(message_id, MsgStatus::DELIVERED);
    ipc_server_.push("outbox.status_update", {
        {"message_id", CborValue::from_string(message_id)},
        {"status",     CborValue::from_string("delivered")},
    });
}

void Outbox::handle_poll_ack(const Bytes& body) {
    struct cbor_load_result res{};
    cbor_item_t* root = cbor_load(body.data(), body.size(), &res);
    if (!root || res.error.code != CBOR_ERR_NONE) { if (root) cbor_decref(&root); return; }

    for (size_t i = 0; i < cbor_map_size(root); ++i) {
        auto p = cbor_map_handle(root)[i];
        if (!cbor_isa_string(p.key)) continue;
        std::string k(reinterpret_cast<char*>(cbor_string_handle(p.key)),
                      cbor_string_length(p.key));
        if (k == "message_ids" && cbor_isa_array(p.value)) {
            for (size_t j = 0; j < cbor_array_size(p.value); ++j) {
                auto* item = cbor_array_handle(p.value)[j];
                if (!cbor_isa_string(item)) continue;
                std::string mid(reinterpret_cast<char*>(cbor_string_handle(item)),
                                cbor_string_length(item));
                store_.set_status(mid, MsgStatus::DELIVERED);
                ipc_server_.push("outbox.status_update", {
                    {"message_id", CborValue::from_string(mid)},
                    {"status",     CborValue::from_string("delivered")},
                });
            }
        }
    }
    cbor_decref(&root);
}

// ── Delivery attempt ──────────────────────────────────────────────────────────

bool Outbox::attempt_delivery(const QueuedMessage& msg, const RecipientInbox& ri) {
    try {
        std::string chan = ensure_channel(bytes_to_hex(ri.key_c_pubkey));
        ar_client_.call("frame.send", {
            {"channel_id", CborValue::from_string(chan)},
            {"payload",    CborValue::from_bytes(msg.delivery_frame)},
        });
        return true;
    } catch (...) {
        return false;
    }
}

// ── Startup burst ─────────────────────────────────────────────────────────────

void Outbox::startup_burst() {
    auto pending = store_.list_pending();
    for (auto& msg : pending) {
        if (!running_) break;
        auto inboxes = store_.get_recipient_inboxes(msg.message_id);
        for (auto& ri : inboxes) {
            if (attempt_delivery(msg, ri)) break;
        }
    }
}

// ── Immediate attempt after enqueue ──────────────────────────────────────────

void Outbox::immediate_attempt(const std::string& message_id) {
    auto msg = store_.get_message(message_id);
    if (!msg || msg->status != MsgStatus::PENDING) return;

    auto inboxes = store_.get_recipient_inboxes(message_id);
    bool ok = false;
    for (auto& ri : inboxes) {
        if (attempt_delivery(*msg, ri)) { ok = true; break; }
    }
    if (!ok) {
        // Schedule retry: exponential backoff within retry window.
        int32_t count = msg->attempt_count + 1;
        int64_t delay = int64_t(60) * (1 << std::min(count - 1, 4)) * 1000; // 60s, 120s, 240s...
        int64_t t = now_ms();
        if (t - msg->enqueued_at_ms + delay > cfg_.retry_window_s * 1000
                || count >= cfg_.max_retries) {
            // Past retry window — passive wait.
            store_.update_attempt(message_id, count, 0);
        } else {
            store_.update_attempt(message_id, count, t + delay);
        }
    }
    replicate_to_siblings(message_id);
}

// ── Sibling replication ───────────────────────────────────────────────────────

void Outbox::replicate_to_siblings(const std::string& message_id) {
    auto msg = store_.get_message(message_id);
    if (!msg) return;
    auto inboxes  = store_.get_recipient_inboxes(message_id);
    auto siblings = store_.list_siblings();

    for (auto& sib : siblings) {
        try {
            std::string chan = ensure_channel(bytes_to_hex(sib.key_c_pubkey));

            cbor_item_t* rf = cbor_new_definite_map(5);
            cbor_map_add(rf, {cbor_build_string("type"),
                              cbor_build_string("outbox_replication_frame")});
            cbor_map_add(rf, {cbor_build_string("message_id"),
                              cbor_build_string(message_id.c_str())});
            cbor_map_add(rf, {cbor_build_string("delivery_frame"),
                              cbor_build_bytestring(msg->delivery_frame.data(),
                                                    msg->delivery_frame.size())});
            cbor_map_add(rf, {cbor_build_string("expires_at"),
                              cbor_build_uint64(static_cast<uint64_t>(msg->expires_at_ms))});

            cbor_item_t* ri_arr = cbor_new_definite_array(inboxes.size());
            for (auto& ri : inboxes) {
                cbor_item_t* e = cbor_new_definite_map(2);
                cbor_map_add(e, {cbor_build_string("inbox_key_c_pubkey"),
                                 cbor_build_bytestring(ri.key_c_pubkey.data(),
                                                       ri.key_c_pubkey.size())});
                cbor_map_add(e, {cbor_build_string("auth_cert"),
                                 cbor_build_bytestring(ri.auth_cert.data(),
                                                       ri.auth_cert.size())});
                cbor_array_push(ri_arr, e);
            }
            cbor_map_add(rf, {cbor_build_string("recipient_inboxes"), ri_arr});

            uint8_t* buf = nullptr; size_t len = 0;
            cbor_serialize_alloc(rf, &buf, &len);
            cbor_decref(&rf);
            if (!buf) continue;
            Bytes payload(buf, buf + len);
            free(buf);

            ar_client_.call("frame.send", {
                {"channel_id", CborValue::from_string(chan)},
                {"payload",    CborValue::from_bytes(payload)},
            });
        } catch (...) {}
    }
}

// ── Retry loop ────────────────────────────────────────────────────────────────

void Outbox::retry_loop() {
    while (running_) {
        std::this_thread::sleep_for(5s);
        if (!running_) break;
        try {
            auto due = store_.list_due(now_ms());
            for (auto& msg : due) {
                auto inboxes = store_.get_recipient_inboxes(msg.message_id);
                bool ok = false;
                for (auto& ri : inboxes) {
                    if (attempt_delivery(msg, ri)) { ok = true; break; }
                }
                int32_t count = msg.attempt_count + 1;
                if (!ok) {
                    int64_t elapsed = now_ms() - msg.enqueued_at_ms;
                    if (elapsed > cfg_.retry_window_s * 1000 || count >= cfg_.max_retries) {
                        store_.update_attempt(msg.message_id, count, 0); // passive wait
                    } else {
                        int64_t delay = int64_t(60) * (1 << std::min(count - 1, 4)) * 1000;
                        store_.update_attempt(msg.message_id, count, now_ms() + delay);
                    }
                }
            }
        } catch (...) {}
    }
}

// ── Maintenance ───────────────────────────────────────────────────────────────

void Outbox::maintenance_loop() {
    while (running_) {
        std::this_thread::sleep_for(60s);
        if (!running_) break;
        try {
            int64_t t = now_ms();
            store_.expire_messages(t);
        } catch (...) {}
    }
}

// ── Channel management ────────────────────────────────────────────────────────

std::string Outbox::ensure_channel(const std::string& key_c_pubkey_hex) {
    auto result = ar_client_.call("channel.list", {});
    if (result.count("channels") && result.at("channels").is_array()) {
        for (auto& cv : result.at("channels").as_array()) {
            if (!cv.is_map()) continue;
            const auto& m = cv.as_map();
            auto rp = m.find("remote_pubkey");
            auto st = m.find("state");
            auto ci = m.find("channel_id");
            if (rp != m.end() && rp->second.is_string()
                    && rp->second.as_string() == key_c_pubkey_hex
                    && st != m.end() && st->second.as_string() == "open"
                    && ci != m.end()) {
                return ci->second.as_string();
            }
        }
    }
    auto r = ar_client_.call("channel.open", {
        {"remote_pubkey", CborValue::from_string(key_c_pubkey_hex)},
        {"anon_level",    CborValue::from_uint(2)},
        {"mode",          CborValue::from_string("message")},
    });
    if (!r.count("channel_id") || !r.at("channel_id").is_string())
        throw std::runtime_error("channel.open failed");
    return r.at("channel_id").as_string();
}

} // namespace sw::outbox
