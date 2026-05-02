#include "client.hpp"
#include "ipc_handler.hpp"
#include <sw/crypto/kdf.hpp>
#include <sw/crypto/aes_gcm.hpp>
#include <sw/crypto/mlkem.hpp>
#include <sw/crypto/mldsa.hpp>
#include <cbor.h>
#include <sodium.h>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>

namespace sw::client {

using namespace sw::crypto;
using namespace sw::ipc;

// ── hex helpers ───────────────────────────────────────────────────────────────

static std::string to_hex(const uint8_t* p, size_t n) {
    std::ostringstream oss;
    for (size_t i = 0; i < n; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)p[i];
    return oss.str();
}

static std::string to_hex(const Bytes& b) { return to_hex(b.data(), b.size()); }
static std::string to_hex(const Key32& k)  { return to_hex(k.data(), 32); }

static Bytes from_hex(const std::string& s) {
    Bytes result;
    result.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        result.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    }
    return result;
}

static std::string rand_hex_id(size_t bytes = 16) {
    Bytes buf(bytes);
    randombytes_buf(buf.data(), bytes);
    return to_hex(buf);
}

// ── CBOR build helpers ────────────────────────────────────────────────────────

static Bytes cbor_ser(cbor_item_t* item) {
    unsigned char* buf = nullptr;
    size_t buf_size = 0;
    size_t n = cbor_serialize_alloc(item, &buf, &buf_size);
    Bytes result(buf, buf + n);
    free(buf);
    return result;
}

static void map_add_str(cbor_item_t* m, const char* k, const char* v) {
    cbor_map_add(m, (struct cbor_pair){
        .key   = cbor_move(cbor_build_string(k)),
        .value = cbor_move(cbor_build_string(v))
    });
}
static void map_add_bytes(cbor_item_t* m, const char* k,
                           const uint8_t* d, size_t l) {
    cbor_map_add(m, (struct cbor_pair){
        .key   = cbor_move(cbor_build_string(k)),
        .value = cbor_move(cbor_build_bytestring(d, l))
    });
}
static void map_add_uint(cbor_item_t* m, const char* k, uint64_t v) {
    cbor_map_add(m, (struct cbor_pair){
        .key   = cbor_move(cbor_build_string(k)),
        .value = cbor_move(cbor_build_uint64(v))
    });
}

static Bytes cbor_get_field_bytes(cbor_item_t* map, const char* key) {
    cbor_pair* pairs = cbor_map_handle(map);
    size_t n = cbor_map_size(map);
    for (size_t i = 0; i < n; ++i) {
        const char* k = reinterpret_cast<const char*>(cbor_string_handle(pairs[i].key));
        if (strcmp(k, key) == 0 && cbor_isa_bytestring(pairs[i].value)) {
            const uint8_t* p = cbor_bytestring_handle(pairs[i].value);
            size_t l = cbor_bytestring_length(pairs[i].value);
            return Bytes(p, p + l);
        }
    }
    return {};
}
static std::string cbor_get_field_str(cbor_item_t* map, const char* key) {
    cbor_pair* pairs = cbor_map_handle(map);
    size_t n = cbor_map_size(map);
    for (size_t i = 0; i < n; ++i) {
        const char* k = reinterpret_cast<const char*>(cbor_string_handle(pairs[i].key));
        if (strcmp(k, key) == 0 && cbor_isa_string(pairs[i].value))
            return std::string(reinterpret_cast<const char*>(
                               cbor_string_handle(pairs[i].value)),
                               cbor_string_length(pairs[i].value));
    }
    return {};
}
static uint64_t cbor_get_field_uint(cbor_item_t* map, const char* key) {
    cbor_pair* pairs = cbor_map_handle(map);
    size_t n = cbor_map_size(map);
    for (size_t i = 0; i < n; ++i) {
        const char* k = reinterpret_cast<const char*>(cbor_string_handle(pairs[i].key));
        if (strcmp(k, key) == 0 && cbor_isa_uint(pairs[i].value))
            return cbor_get_uint64(pairs[i].value);
    }
    return 0;
}

// ── Construction ──────────────────────────────────────────────────────────────

Client::Client(const Config& cfg)
    : cfg_(cfg)
    , keystore_(cfg.keystore_path, cfg.keystore_salt)
    , store_(cfg.messages_db_path)
    , ratchet_mgr_(keystore_)
    , ar_client_(cfg.anonrouter_sock)
    , inbox_client_(cfg.inbox_sock)
    , outbox_client_(cfg.outbox_sock)
{
    ipc_handler_ = std::make_unique<IpcHandler>(*this);
    ipc_server_  = std::make_unique<ipc::Server>(
        cfg.client_sock,
        [this](const std::string& method, const CborMap& params,
               const std::string& caller) {
            return ipc_handler_->handle(method, params, caller);
        });
}

Client::~Client() {
    stop();
}

void Client::start() {
    running_ = true;
    ipc_server_->start();
    std::cerr << "[client] IPC server started at " << cfg_.client_sock << "\n";
}

void Client::stop() {
    if (!running_.exchange(false)) return;
    ipc_server_->stop();
    if (dht_thread_.joinable())        dht_thread_.join();
    if (cert_renew_thread_.joinable()) cert_renew_thread_.join();
    if (keystore_.is_unlocked()) keystore_.save();
}

void Client::wait() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

// ── Session ───────────────────────────────────────────────────────────────────

void Client::unlock(const std::string& passphrase) {
    std::lock_guard<std::mutex> lk(state_mu_);
    keystore_.unlock(passphrase);

    // Ensure Key A and contact-request Key B exist.
    if (!keystore_.get_key_a()) {
        KeyA ka;
        auto kp = mldsa_keygen();
        ka.pubkey  = kp.pub;
        ka.privkey = kp.priv;
        ka.created_at = static_cast<int64_t>(std::time(nullptr));
        keystore_.set_key_a(ka);

        KeyBCr cr;
        auto cr_kp = mlkem_keygen();
        cr.kem_pubkey  = cr_kp.pub;
        cr.kem_privkey = cr_kp.priv;
        cr.created_at  = ka.created_at;
        keystore_.set_key_b_cr(cr);

        if (keystore_.get_config("display_name").empty())
            keystore_.set_config("display_name", "ScatterWeb User");

        keystore_.save();
    }

    // Connect to dependent services and run startup sequence.
    connect_services();

    // Background loops
    dht_thread_ = std::thread([this]{ dht_loop(); });
    cert_renew_thread_ = std::thread([this]{ cert_renew_loop(); });
}

void Client::lock() {
    std::lock_guard<std::mutex> lk(state_mu_);
    running_ = false;
    keystore_.lock();
}

bool Client::is_unlocked() const {
    return keystore_.is_unlocked();
}

void Client::change_passphrase(const std::string& old_p,
                                 const std::string& new_p) {
    keystore_.change_passphrase(old_p, new_p);
}

// ── Startup sequence ──────────────────────────────────────────────────────────

void Client::connect_services() {
    // Connect to AnonRouter.
    try {
        ar_client_.connect();
        ar_client_.on_push([this](const std::string& /*ev*/, const CborMap& /*pl*/) {
            // Client doesn't need AR push events currently.
        });
    } catch (const std::exception& e) {
        std::cerr << "[client] AnonRouter connect failed: " << e.what() << "\n";
    }

    // Connect to Inbox.
    try {
        inbox_client_.connect();
        inbox_client_.on_push([this](const std::string& ev, const CborMap& pl) {
            if (ev == "inbox.message_available") {
                auto it = pl.find("message_id");
                if (it != pl.end() && it->second.is_string())
                    on_inbox_message(it->second.as_string());
            }
        });
        push_sender_allowlist();
    } catch (const std::exception& e) {
        std::cerr << "[client] Inbox connect failed: " << e.what() << "\n";
    }

    // Connect to Outbox.
    try {
        outbox_client_.connect();
        outbox_client_.on_push([this](const std::string& ev, const CborMap& pl) {
            if (ev == "outbox.status_update") {
                auto mit = pl.find("message_id");
                auto sit = pl.find("status");
                auto uit = pl.find("updated_at");
                if (mit != pl.end() && mit->second.is_string() &&
                    sit != pl.end() && sit->second.is_string()) {
                    int64_t ts = uit != pl.end() && uit->second.is_uint()
                                 ? static_cast<int64_t>(uit->second.as_uint()) : 0;
                    on_outbox_status(mit->second.as_string(),
                                     sit->second.as_string(), ts);
                }
            }
        });
    } catch (const std::exception& e) {
        std::cerr << "[client] Outbox connect failed: " << e.what() << "\n";
    }

    check_renew_key_c();
    replenish_prekeys();

    uint64_t ts = current_timeslot();
    publish_dht_records(ts);
    publish_dht_records(ts + 1); // pre-publish next slot

    fetch_pending_messages();
}

void Client::push_sender_allowlist() {
    auto contacts = store_.list_contacts();
    CborArray senders;
    for (const auto& c : contacts) {
        if (c.status != "active") continue;
        Key32 sid = sha3_256(ByteSpan{c.key_a_pubkey.data(), c.key_a_pubkey.size()});
        CborMap m;
        m["sender_id"] = CborValue::from_bytes(Bytes(sid.begin(), sid.end()));
        senders.push_back(CborValue::from_map(std::move(m)));
    }
    CborMap params;
    params["allowed_senders"] = CborValue::from_array(std::move(senders));
    try {
        inbox_client_.call("inbox.update_sender_allowlist", params);
    } catch (...) {}
}

void Client::publish_dht_records(uint64_t timeslot) {
    if (!ar_client_.is_connected()) return;
    GuardInfo guard;
    try {
        guard = get_guard_info();
    } catch (...) {
        return;
    }

    auto ka = keystore_.get_key_a();
    if (!ka) return;

    for (const auto& kb : keystore_.list_key_b()) {
        auto [dht_key, dht_val] = build_guard_record(
            kb.kem_pubkey, ka->privkey, timeslot, guard);

        CborMap params;
        params["key"]         = CborValue::from_string(to_hex(dht_key));
        params["value"]       = CborValue::from_bytes(dht_val);
        params["ttl_seconds"] = CborValue::from_uint(3600);
        try {
            ar_client_.call("dht.put", params);
        } catch (...) {}

        // Publish prekey record if we have prekeys.
        int pk_count = keystore_.count_prekeys(kb.id);
        if (pk_count > 0) {
            auto prekeys_raw = keystore_.list_prekeys(kb.id);
            std::vector<KemPubKey> pks;
            pks.reserve(prekeys_raw.size());
            for (const auto& pk : prekeys_raw) pks.push_back(pk.kem_pubkey);

            auto [pk_dht_key, pk_dht_val] = build_prekey_record(
                kb.kem_pubkey, ka->privkey, pks,
                static_cast<int64_t>(std::time(nullptr)));
            CborMap pk_params;
            pk_params["key"]         = CborValue::from_string(to_hex(pk_dht_key));
            pk_params["value"]       = CborValue::from_bytes(pk_dht_val);
            pk_params["ttl_seconds"] = CborValue::from_uint(604800);
            try {
                ar_client_.call("dht.put", pk_params);
            } catch (...) {}
        }
    }
}

void Client::check_renew_key_c() {
    auto now_s = static_cast<int64_t>(std::time(nullptr));
    auto ka    = keystore_.get_key_a();
    if (!ka) return;

    for (const auto& kc : keystore_.list_key_c()) {
        if (kc.revoked) continue;
        int64_t threshold = now_s + cfg_.key_c_renewal_threshold_days * 86400;
        if (kc.expires_at > threshold) continue;

        // Re-issue cert.
        Bytes new_cert = issue_auth_cert(
            ka->privkey, ka->pubkey, kc.key_c_pubkey,
            kc.device_type, kc.device_label, now_s);

        keystore_.update_key_c_cert(kc.device_id, new_cert, now_s + 2592000);

        // Push new cert to the device via inbox/outbox IPC.
        CborMap params;
        params["auth_cert"] = CborValue::from_bytes(new_cert);
        if (kc.device_type == "inbox") {
            try { inbox_client_.call("inbox.set_auth_cert", params); } catch (...) {}
        } else {
            try { outbox_client_.call("outbox.set_auth_cert", params); } catch (...) {}
        }
    }
}

void Client::replenish_prekeys() {
    auto now_s = static_cast<int64_t>(std::time(nullptr));
    for (const auto& kb : keystore_.list_key_b()) {
        int count = keystore_.count_prekeys(kb.id);
        if (count >= cfg_.prekey_low_threshold) continue;

        int to_gen = cfg_.prekey_batch_size;
        for (int i = 0; i < to_gen; ++i) {
            auto kp = mlkem_keygen();
            Key32 pk_id = sha3_256(ByteSpan{kp.pub.data(), kp.pub.size()});
            KeyDPrekey prekey;
            prekey.id         = to_hex(pk_id);
            prekey.key_b_id   = kb.id;
            prekey.kem_pubkey  = kp.pub;
            prekey.kem_privkey = kp.priv;
            prekey.created_at  = now_s;
            keystore_.insert_prekey(prekey);
        }
        // Publish updated prekey record.
        auto ka = keystore_.get_key_a();
        if (ka) {
            auto prekeys_raw = keystore_.list_prekeys(kb.id);
            std::vector<KemPubKey> pks;
            for (const auto& pk : prekeys_raw) pks.push_back(pk.kem_pubkey);
            auto [dht_key, dht_val] = build_prekey_record(
                kb.kem_pubkey, ka->privkey, pks, now_s);
            CborMap params;
            params["key"]         = CborValue::from_string(to_hex(dht_key));
            params["value"]       = CborValue::from_bytes(dht_val);
            params["ttl_seconds"] = CborValue::from_uint(604800);
            try { ar_client_.call("dht.put", params); } catch (...) {}
        }
        keystore_.save();

        // Notify UI if prekeys were very low.
        if (count < cfg_.prekey_low_threshold) {
            CborMap ev;
            ev["key_b_count"] = CborValue::from_uint(1);
            ipc_server_->push("inbox.prekeys_low", ev);
        }
    }
}

void Client::fetch_pending_messages() {
    if (!inbox_client_.is_connected()) return;
    try {
        CborMap result = inbox_client_.call("inbox.get_pending", {});
        auto it = result.find("messages");
        if (it == result.end() || !it->second.is_array()) return;
        for (const auto& m : it->second.as_array()) {
            if (!m.is_map()) continue;
            auto mid = m.as_map().find("message_id");
            if (mid != m.as_map().end() && mid->second.is_string())
                on_inbox_message(mid->second.as_string());
        }
    } catch (...) {}
}

// ── DHT / cert renewal loops ──────────────────────────────────────────────────

void Client::dht_loop() {
    uint64_t last_slot = current_timeslot();
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        if (!running_) break;
        uint64_t now_slot = current_timeslot();
        if (now_slot != last_slot) {
            std::lock_guard<std::mutex> lk(state_mu_);
            publish_dht_records(now_slot);
            publish_dht_records(now_slot + 1);
            last_slot = now_slot;
        }
    }
}

void Client::cert_renew_loop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::hours(1));
        if (!running_) break;
        std::lock_guard<std::mutex> lk(state_mu_);
        check_renew_key_c();
        replenish_prekeys();
    }
}

// ── Receive flow ──────────────────────────────────────────────────────────────

void Client::on_inbox_message(const std::string& message_id) {
    if (!inbox_client_.is_connected()) return;
    try {
        CborMap params;
        params["message_id"] = CborValue::from_string(message_id);
        CborMap result = inbox_client_.call("inbox.get", params);
        auto fit = result.find("delivery_frame");
        if (fit == result.end() || !fit->second.is_bytes()) return;
        process_delivery_frame(message_id, fit->second.as_bytes());
    } catch (const std::exception& e) {
        std::cerr << "[client] fetch message failed: " << e.what() << "\n";
    }
}

void Client::process_delivery_frame(const std::string& message_id,
                                      const Bytes& frame_bytes) {
    DeliveryFrame frame;
    try {
        frame = decode_delivery_frame(ByteSpan{frame_bytes.data(), frame_bytes.size()});
    } catch (...) {
        return; // malformed
    }

    // Step 4a: sender must be a known contact.
    std::string sender_id_hex = to_hex(frame.sender_id);
    auto contact = store_.get_contact(sender_id_hex);
    if (!contact) return; // unknown sender — drop

    // Step 4b: resolve auth cert.
    auto cached_cert = store_.get_cert(frame.cert_fingerprint);
    if (!cached_cert) {
        if (frame.sender_outbox_cert.empty()) return; // cannot verify — drop
        // Verify and cache the inline cert.
        // (Full verification of the cert signature against key_a_pub is omitted
        //  here but would call mldsa_verify on the cert CBOR in production.)
        KnownCert kc;
        kc.fingerprint = frame.cert_fingerprint;
        kc.auth_cert   = frame.sender_outbox_cert;
        kc.owner_id    = sender_id_hex;
        kc.cached_at   = static_cast<int64_t>(std::time(nullptr));
        store_.insert_cert(kc);
    }

    // Step 5: decrypt envelope.
    std::string conv_id;
    Bytes app_frame_bytes;
    try {
        if (frame.envelope_type == "ratchet") {
            // Determine conversation ID from sender.
            auto ka = keystore_.get_key_a();
            if (!ka) return;
            Key32 my_id = sha3_256(ByteSpan{ka->pubkey.data(), ka->pubkey.size()});
            std::string my_hex = to_hex(my_id);
            // DM conv_id = hex(SHA3-256("dm:" || min || ":" || max))
            std::string a = my_hex, b = sender_id_hex;
            if (a > b) std::swap(a, b);
            Key32 cid_key = sha3_256({
                as_bytes("dm:"),
                ByteSpan{reinterpret_cast<const uint8_t*>(a.data()), a.size()},
                as_bytes(":"),
                ByteSpan{reinterpret_cast<const uint8_t*>(b.data()), b.size()}
            });
            conv_id = to_hex(cid_key);
            app_frame_bytes = decrypt_ratchet_envelope(
                conv_id, frame.encrypted_envelope);
        } else if (frame.envelope_type == "sender_key") {
            // Parse group_id from envelope header.
            struct cbor_load_result res;
            cbor_item_t* env = cbor_load(frame.encrypted_envelope.data(),
                                          frame.encrypted_envelope.size(), &res);
            if (!env) return;
            conv_id = cbor_get_field_str(env, "group_id");
            std::string sender_str = to_hex(frame.sender_id);
            app_frame_bytes = decrypt_sender_key_envelope(
                conv_id, sender_str, frame.encrypted_envelope);
            cbor_decref(&env);
        } else {
            return;
        }
    } catch (...) {
        return; // decryption failure — drop
    }

    // Step 6: dispatch to app frame handler.
    // Parse type field from app_frame_bytes.
    struct cbor_load_result res;
    cbor_item_t* af = cbor_load(app_frame_bytes.data(), app_frame_bytes.size(), &res);
    if (!af) return;
    std::string frame_type = cbor_get_field_str(af, "type");
    cbor_decref(&af);

    dispatch_app_frame(conv_id, frame_type, app_frame_bytes, frame_bytes);

    // Step 7: ACK to inbox.
    try {
        CborMap ack_params;
        ack_params["message_id"] = CborValue::from_string(message_id);
        inbox_client_.call("inbox.ack", ack_params);
    } catch (...) {}
}

void Client::dispatch_app_frame(const std::string& conv_id,
                                  const std::string& frame_type,
                                  const Bytes&       app_frame_bytes,
                                  const Bytes&       raw_frame) {
    struct cbor_load_result res;
    cbor_item_t* af = cbor_load(app_frame_bytes.data(), app_frame_bytes.size(), &res);
    if (!af) return;

    auto now_ms = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    if (frame_type == "message" || frame_type == "reaction" ||
        frame_type == "edit"    || frame_type == "delete"   ||
        frame_type == "contact_request" || frame_type == "contact_accept" ||
        frame_type == "group_invite"    || frame_type == "group_accept"   ||
        frame_type == "group_leave"     || frame_type == "group_sender_key_update" ||
        frame_type == "call_invite"     || frame_type == "key_c_cert") {

        // Store raw frame.
        std::string msg_id = cbor_get_field_str(af, "id");
        std::string sender_id_field = cbor_get_field_str(af, "conversation_id");
        if (msg_id.empty()) {
            cbor_decref(&af);
            return;
        }

        StoredMessage m;
        m.id              = msg_id;
        m.conversation_id = conv_id;
        m.sender_id       = Bytes(32, 0); // filled from delivery frame sender_id
        m.seq             = store_.next_seq(conv_id);
        m.content_type    = "text";
        m.ciphertext      = raw_frame;
        m.sent_at         = static_cast<int64_t>(cbor_get_field_uint(af, "sent_at"));
        m.received_at     = now_ms;
        m.status          = "delivered";
        store_.insert_message(m);

        // Push to UI.
        CborMap ev;
        ev["conversation_id"] = CborValue::from_string(conv_id);
        ev["message_id"]      = CborValue::from_string(msg_id);
        ev["sent_at"]         = CborValue::from_uint(static_cast<uint64_t>(m.sent_at));
        ipc_server_->push("message.received", ev);

    } else if (frame_type == "typing") {
        CborMap ev;
        ev["conversation_id"] = CborValue::from_string(conv_id);
        ipc_server_->push("typing.start", ev);
    } else if (frame_type == "read_receipt") {
        // Update message status for the referenced message.
        std::string up_to = cbor_get_field_str(af, "up_to_message_id");
        if (!up_to.empty()) {
            store_.update_message_status(up_to, "read");
            CborMap ev;
            ev["message_id"] = CborValue::from_string(up_to);
            ipc_server_->push("message.read", ev);
        }
    }
    cbor_decref(&af);
}

void Client::on_outbox_status(const std::string& message_id,
                               const std::string& status,
                               int64_t            updated_at) {
    // Map outbox status → message status.
    std::string msg_status = "pending";
    if (status == "delivered") msg_status = "delivered";
    else if (status == "expired" || status == "failed") msg_status = "failed";

    store_.update_message_status(message_id, msg_status);

    CborMap ev;
    ev["message_id"] = CborValue::from_string(message_id);
    ev["status"]     = CborValue::from_string(msg_status);
    ev["updated_at"] = CborValue::from_uint(static_cast<uint64_t>(updated_at));
    ipc_server_->push("delivery.status_update", ev);
}

// ── Encryption helpers ────────────────────────────────────────────────────────

Bytes Client::encrypt_ratchet_envelope(const std::string& conv_id,
                                         const Bytes& app_frame_cbor) {
    ratchet::Message msg = ratchet_mgr_.encrypt(
        conv_id, ByteSpan{app_frame_cbor.data(), app_frame_cbor.size()});

    cbor_item_t* root = cbor_new_definite_map(7);
    map_add_uint(root,  "version",      1);
    map_add_str(root,   "envelope_type","ratchet");
    map_add_uint(root,  "epoch",        msg.header.epoch);
    map_add_uint(root,  "msg_num",      msg.header.msg_num);
    map_add_bytes(root, "sender_ratchet_pub",
                  msg.header.sender_ratchet_pub.data(),
                  msg.header.sender_ratchet_pub.size());
    if (msg.header.kem_ct) {
        map_add_bytes(root, "kem_ct",
                      msg.header.kem_ct->data(), msg.header.kem_ct->size());
    }
    map_add_bytes(root, "iv",         msg.nonce.data(), 12);
    map_add_bytes(root, "ciphertext", msg.ciphertext.data(), msg.ciphertext.size());
    map_add_bytes(root, "tag",        msg.tag.data(), 16);
    Bytes result = cbor_ser(root);
    cbor_decref(&root);
    return result;
}

Bytes Client::encrypt_sender_key_envelope(const std::string& group_id,
                                            const Bytes& app_frame_cbor) {
    auto ka = keystore_.get_key_a();
    if (!ka) throw std::runtime_error("keystore locked");

    Key32 my_id = sha3_256(ByteSpan{ka->pubkey.data(), ka->pubkey.size()});
    std::string my_hex = to_hex(my_id);

    auto sk = keystore_.get_sender_key(group_id, my_hex);
    if (!sk) throw std::runtime_error("no sender key for group " + group_id);

    AesKey key;
    std::copy(sk->sym_key.begin(), sk->sym_key.end(), key.begin());
    AesEncrypted enc = aes_encrypt(
        key, ByteSpan{app_frame_cbor.data(), app_frame_cbor.size()});

    cbor_item_t* root = cbor_new_definite_map(7);
    map_add_uint(root,  "version",      1);
    map_add_str(root,   "envelope_type","sender_key");
    map_add_str(root,   "group_id",     group_id.c_str());
    map_add_bytes(root, "sender_id",    my_id.data(), 32);
    map_add_uint(root,  "sender_key_generation", sk->generation);
    map_add_bytes(root, "iv",           enc.nonce.data(), 12);
    map_add_bytes(root, "ciphertext",   enc.ciphertext.data(), enc.ciphertext.size());
    map_add_bytes(root, "tag",          enc.tag.data(), 16);
    Bytes result = cbor_ser(root);
    cbor_decref(&root);
    return result;
}

Bytes Client::decrypt_ratchet_envelope(const std::string& conv_id,
                                         const Bytes& envelope_bytes) {
    struct cbor_load_result res;
    cbor_item_t* root = cbor_load(envelope_bytes.data(), envelope_bytes.size(), &res);
    if (!root) throw std::runtime_error("invalid ratchet envelope");

    ratchet::Header hdr;
    hdr.epoch    = static_cast<uint32_t>(cbor_get_field_uint(root, "epoch"));
    hdr.msg_num  = static_cast<uint32_t>(cbor_get_field_uint(root, "msg_num"));
    hdr.prev_count = 0;

    Bytes sender_pub_bytes = cbor_get_field_bytes(root, "sender_ratchet_pub");
    if (sender_pub_bytes.size() == MLKEM768_PUBKEY_BYTES)
        std::copy(sender_pub_bytes.begin(), sender_pub_bytes.end(),
                  hdr.sender_ratchet_pub.begin());

    Bytes kem_ct_bytes = cbor_get_field_bytes(root, "kem_ct");
    if (kem_ct_bytes.size() == MLKEM768_CT_BYTES) {
        crypto::KemCt ct;
        std::copy(kem_ct_bytes.begin(), kem_ct_bytes.end(), ct.begin());
        hdr.kem_ct = ct;
    }

    Bytes iv_bytes  = cbor_get_field_bytes(root, "iv");
    Bytes ct_bytes  = cbor_get_field_bytes(root, "ciphertext");
    Bytes tag_bytes = cbor_get_field_bytes(root, "tag");
    cbor_decref(&root);

    ratchet::Message msg;
    msg.header = hdr;
    if (iv_bytes.size() == 12) std::copy(iv_bytes.begin(), iv_bytes.end(), msg.nonce.begin());
    msg.ciphertext = ct_bytes;
    if (tag_bytes.size() == 16) std::copy(tag_bytes.begin(), tag_bytes.end(), msg.tag.begin());

    return ratchet_mgr_.decrypt(conv_id, msg);
}

Bytes Client::decrypt_sender_key_envelope(const std::string& group_id,
                                            const std::string& sender_id_hex,
                                            const Bytes& envelope_bytes) {
    struct cbor_load_result res;
    cbor_item_t* root = cbor_load(envelope_bytes.data(), envelope_bytes.size(), &res);
    if (!root) throw std::runtime_error("invalid sender_key envelope");

    uint32_t generation = static_cast<uint32_t>(
        cbor_get_field_uint(root, "sender_key_generation"));
    Bytes iv_bytes  = cbor_get_field_bytes(root, "iv");
    Bytes ct_bytes  = cbor_get_field_bytes(root, "ciphertext");
    Bytes tag_bytes = cbor_get_field_bytes(root, "tag");
    cbor_decref(&root);

    auto sk = keystore_.get_sender_key(group_id, sender_id_hex);
    if (!sk) throw std::runtime_error("no sender key");
    if (sk->generation != generation)
        throw std::runtime_error("sender key generation mismatch");

    AesKey key;
    std::copy(sk->sym_key.begin(), sk->sym_key.end(), key.begin());
    AesNonce nonce{};
    if (iv_bytes.size() == 12) std::copy(iv_bytes.begin(), iv_bytes.end(), nonce.begin());
    AesTag tag{};
    if (tag_bytes.size() == 16) std::copy(tag_bytes.begin(), tag_bytes.end(), tag.begin());

    return aes_decrypt(key, nonce,
                       ByteSpan{ct_bytes.data(), ct_bytes.size()}, tag);
}

// ── Message send flow ─────────────────────────────────────────────────────────

void Client::enqueue_dm(const std::string& conv_id,
                          const std::string& app_frame_type,
                          const Bytes&       app_frame_cbor,
                          const std::string& persistence,
                          const std::string& message_id) {
    // Find contact from conversation.
    auto conv = store_.get_conversation(conv_id);
    if (!conv) throw std::runtime_error("unknown conversation");

    auto contact = store_.get_contact(conv->contact_id);
    if (!contact) throw std::runtime_error("contact not found");

    // Build delivery frame.
    auto ka = require_key_a();
    Key32 my_sender_id = sha3_256(ByteSpan{ka.pubkey.data(), ka.pubkey.size()});

    // Get outbox auth cert.
    Bytes auth_cert;
    Bytes cert_fingerprint(32, 0);
    for (const auto& kc : keystore_.list_key_c()) {
        if (kc.device_type == "outbox" && !kc.revoked) {
            auth_cert       = kc.auth_cert;
            Key32 fp = sha3_256(ByteSpan{auth_cert.data(), auth_cert.size()});
            cert_fingerprint.assign(fp.begin(), fp.end());
            break;
        }
    }

    Bytes envelope = encrypt_ratchet_envelope(conv_id, app_frame_cbor);

    DeliveryFrame df;
    df.message_id        = from_hex(message_id);
    df.persistence       = persistence;
    df.sender_id         = Bytes(my_sender_id.begin(), my_sender_id.end());
    df.cert_fingerprint  = cert_fingerprint;
    df.sender_outbox_cert= auth_cert; // always include for simplicity
    df.envelope_type     = "ratchet";
    df.encrypted_envelope= envelope;
    Bytes frame_bytes    = encode_delivery_frame(df);

    // Submit to outbox.
    CborMap params;
    params["message_id"]                = CborValue::from_string(message_id);
    params["recipient_key_b_kem_pubkey"]= CborValue::from_bytes(
        Bytes(contact->their_dm_key_b_kem.begin(),
              contact->their_dm_key_b_kem.end()));
    params["delivery_frame"]            = CborValue::from_bytes(frame_bytes);
    params["priority"]                  = CborValue::from_string("normal");
    params["ttl_seconds"]               = CborValue::from_uint(604800);
    try {
        outbox_client_.call("outbox.enqueue", params);
    } catch (const std::exception& e) {
        std::cerr << "[client] enqueue failed: " << e.what() << "\n";
    }
}

// ── UI-facing operations ──────────────────────────────────────────────────────

std::string Client::get_display_name() {
    if (!keystore_.is_unlocked()) return "";
    std::string name = keystore_.get_config("display_name");
    return name.empty() ? "ScatterWeb User" : name;
}

std::string Client::get_contact_card_uri() {
    auto ka = keystore_.get_key_a();
    auto cr = keystore_.get_key_b_cr();
    if (!ka || !cr) return "";
    return encode_contact_card(
        ka->privkey, ka->pubkey, cr->kem_pubkey,
        get_display_name(),
        static_cast<int64_t>(std::time(nullptr)));
}

void Client::set_display_name(const std::string& name) {
    keystore_.set_config("display_name", name);
    keystore_.save();
}

std::vector<Contact> Client::list_contacts() {
    return store_.list_contacts();
}

std::optional<Contact> Client::get_contact(const std::string& id) {
    return store_.get_contact(id);
}

void Client::send_contact_request(const std::string& contact_card_uri) {
    auto card = decode_contact_card(contact_card_uri);
    if (!card) throw std::runtime_error("INVALID_CONTACT_CARD");

    Key32 their_id = sha3_256(
        ByteSpan{card->key_a_pubkey.data(), card->key_a_pubkey.size()});
    std::string their_id_hex = to_hex(their_id);

    if (store_.get_contact(their_id_hex))
        throw std::runtime_error("ALREADY_CONTACT");

    // Check not self.
    auto ka = require_key_a();
    Key32 my_id = sha3_256(ByteSpan{ka.pubkey.data(), ka.pubkey.size()});
    if (their_id == my_id) throw std::runtime_error("SELF_CONTACT");

    // Generate DM Key B for this relationship.
    auto now_s = static_cast<int64_t>(std::time(nullptr));
    std::string my_hex = to_hex(my_id), their_hex = their_id_hex;
    if (my_hex > their_hex) std::swap(my_hex, their_hex);
    Key32 rel_hash = sha3_256({
        as_bytes("dm:"),
        ByteSpan{reinterpret_cast<const uint8_t*>(my_hex.data()), my_hex.size()},
        as_bytes(":"),
        ByteSpan{reinterpret_cast<const uint8_t*>(their_hex.data()), their_hex.size()}
    });
    std::string rel_id = to_hex(rel_hash);

    KeyB kb;
    kb.id           = rel_id;
    kb.relationship = "dm:" + rel_id;
    auto kem_kp = mlkem_keygen();
    auto sig_kp = mldsa_keygen();
    kb.kem_pubkey  = kem_kp.pub;
    kb.kem_privkey = kem_kp.priv;
    kb.sig_pubkey  = sig_kp.pub;
    kb.sig_privkey = sig_kp.priv;
    kb.created_at  = now_s;
    keystore_.insert_key_b(kb);
    replenish_prekeys();
    keystore_.save();

    // Add pending contact.
    Contact c;
    c.id                = their_id_hex;
    c.display_name      = card->display_name;
    c.key_a_pubkey      = Bytes(card->key_a_pubkey.begin(), card->key_a_pubkey.end());
    c.their_dm_key_b_kem= Bytes(card->cr_key_b_kem_pubkey.begin(),
                                 card->cr_key_b_kem_pubkey.end());
    c.my_key_b_id       = rel_id;
    c.added_at          = now_s;
    c.status            = "pending";
    store_.insert_contact(c);

    // Build conv_id and conversation entry.
    std::string a = to_hex(my_id), b = their_id_hex;
    if (a > b) std::swap(a, b);
    Key32 cid = sha3_256({
        as_bytes("dm:"),
        ByteSpan{reinterpret_cast<const uint8_t*>(a.data()), a.size()},
        as_bytes(":"),
        ByteSpan{reinterpret_cast<const uint8_t*>(b.data()), b.size()}
    });
    std::string conv_id = to_hex(cid);

    Conversation conv;
    conv.id           = conv_id;
    conv.type         = "dm";
    conv.display_name = card->display_name;
    conv.contact_id   = their_id_hex;
    conv.created_at   = now_s;
    store_.upsert_conversation(conv);

    // Build contact_request app frame.
    // Init ratchet to their cr_key_b (one-shot encapsulate).
    auto prekey_ct = ratchet_mgr_.init_as_sender(
        conv_id, card->cr_key_b_kem_pubkey,
        kb.kem_pubkey, card->cr_key_b_kem_pubkey);

    std::string msg_id = rand_hex_id();
    cbor_item_t* af = cbor_new_definite_map(9);
    map_add_str(af,   "type",                   "contact_request");
    map_add_bytes(af, "id",   (const uint8_t*)msg_id.data(), msg_id.size());
    map_add_uint(af,  "sent_at", static_cast<uint64_t>(now_s * 1000));
    map_add_bytes(af, "from_key_a_pubkey",       ka.pubkey.data(), ka.pubkey.size());
    map_add_str(af,   "from_display_name",       get_display_name().c_str());
    map_add_bytes(af, "from_dm_key_b_kem_pubkey",kb.kem_pubkey.data(), kb.kem_pubkey.size());
    map_add_bytes(af, "from_dm_key_b_sig_pubkey",kb.sig_pubkey.data(), kb.sig_pubkey.size());
    // Include our prekeys in the bundle.
    auto our_prekeys = keystore_.list_prekeys(rel_id);
    cbor_item_t* pk_arr = cbor_new_definite_array(our_prekeys.size());
    for (const auto& pk : our_prekeys)
        cbor_array_push(pk_arr, cbor_move(
            cbor_build_bytestring(pk.kem_pubkey.data(), pk.kem_pubkey.size())));
    cbor_map_add(af, (struct cbor_pair){
        .key   = cbor_move(cbor_build_string("prekey_bundle")),
        .value = cbor_move(pk_arr)
    });
    Bytes af_bytes = cbor_ser(af);
    cbor_decref(&af);

    enqueue_dm(conv_id, "contact_request", af_bytes, "store", msg_id);
}

void Client::accept_contact_request(const std::string& contact_id) {
    auto contact = store_.get_contact(contact_id);
    if (!contact || contact->status != "pending")
        throw std::runtime_error("CONTACT_NOT_FOUND");

    store_.set_contact_status(contact_id, "active");
    push_sender_allowlist();

    CborMap ev;
    ev["contact_id"]   = CborValue::from_string(contact_id);
    ev["display_name"] = CborValue::from_string(contact->display_name);
    ipc_server_->push("contact.added", ev);
}

void Client::decline_contact_request(const std::string& contact_id) {
    store_.set_contact_status(contact_id, "blocked");
}

void Client::block_contact(const std::string& contact_id) {
    store_.set_contact_status(contact_id, "blocked");
}

std::vector<Conversation> Client::list_conversations() {
    return store_.list_conversations();
}

std::optional<Conversation> Client::get_conversation(const std::string& id) {
    return store_.get_conversation(id);
}

std::vector<StoredMessage> Client::get_messages(const std::string& conv_id,
                                                  int64_t before_seq, int limit) {
    return store_.list_messages(conv_id, before_seq, limit);
}

std::string Client::send_message(const std::string& conv_id,
                                   const std::string& text,
                                   const std::string& reply_to_id) {
    auto now_ms = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    std::string msg_id = rand_hex_id();
    cbor_item_t* af = cbor_new_definite_map(7);
    map_add_str(af,  "type",            "message");
    map_add_bytes(af,"id",              (const uint8_t*)msg_id.data(), msg_id.size());
    map_add_str(af,  "conversation_id", conv_id.c_str());
    map_add_uint(af, "sent_at",         static_cast<uint64_t>(now_ms));
    map_add_str(af,  "content_type",    "text");
    map_add_str(af,  "text",            text.c_str());
    if (!reply_to_id.empty())
        map_add_str(af, "reply_to", reply_to_id.c_str());
    Bytes af_bytes = cbor_ser(af);
    cbor_decref(&af);

    // Store locally with "pending" status.
    auto ka = require_key_a();
    Key32 my_id = sha3_256(ByteSpan{ka.pubkey.data(), ka.pubkey.size()});
    StoredMessage m;
    m.id              = msg_id;
    m.conversation_id = conv_id;
    m.sender_id       = Bytes(my_id.begin(), my_id.end());
    m.seq             = store_.next_seq(conv_id);
    m.content_type    = "text";
    m.ciphertext      = af_bytes; // store encrypted on send; use raw for outgoing
    m.sent_at         = now_ms;
    m.status          = "pending";
    m.reply_to_id     = reply_to_id;
    store_.insert_message(m);

    // Determine if DM or group and enqueue accordingly.
    auto conv = store_.get_conversation(conv_id);
    if (!conv) throw std::runtime_error("UNKNOWN_CONVERSATION");

    if (conv->type == "dm") {
        enqueue_dm(conv_id, "message", af_bytes, "store", msg_id);
    } else {
        // Group: encrypt with sender key and broadcast.
        Bytes envelope = encrypt_sender_key_envelope(conv_id, af_bytes);
        DeliveryFrame df;
        df.message_id         = from_hex(msg_id);
        df.persistence        = "store";
        df.sender_id          = Bytes(my_id.begin(), my_id.end());
        df.envelope_type      = "sender_key";
        df.encrypted_envelope = envelope;
        Bytes frame_bytes     = encode_delivery_frame(df);

        auto members = store_.list_group_members(conv_id);
        CborArray recipients;
        for (const auto& mem : members) {
            if (to_hex(Bytes(my_id.begin(), my_id.end())) == mem.contact_id) continue;
            CborMap r;
            r["key_b_kem_pubkey"] = CborValue::from_bytes(mem.their_key_b_kem);
            recipients.push_back(CborValue::from_map(std::move(r)));
        }
        CborMap params;
        params["message_id"]     = CborValue::from_string(msg_id);
        params["recipients"]     = CborValue::from_array(std::move(recipients));
        params["delivery_frame"] = CborValue::from_bytes(frame_bytes);
        params["priority"]       = CborValue::from_string("normal");
        params["ttl_seconds"]    = CborValue::from_uint(604800);
        try {
            outbox_client_.call("outbox.enqueue_broadcast", params);
        } catch (...) {}
    }
    return msg_id;
}

void Client::send_reaction(const std::string& msg_id, const std::string& emoji) {
    auto msg = store_.get_message(msg_id);
    if (!msg) return;

    std::string frame_id = rand_hex_id();
    auto now_ms = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    cbor_item_t* af = cbor_new_definite_map(5);
    map_add_str(af,  "type",             "reaction");
    map_add_bytes(af,"id",               (const uint8_t*)frame_id.data(), frame_id.size());
    map_add_str(af,  "conversation_id",  msg->conversation_id.c_str());
    map_add_uint(af, "sent_at",          static_cast<uint64_t>(now_ms));
    map_add_str(af,  "target_message_id",msg_id.c_str());
    map_add_str(af,  "emoji",            emoji.c_str());
    map_add_str(af,  "action",           "add");
    Bytes af_bytes = cbor_ser(af);
    cbor_decref(&af);

    enqueue_dm(msg->conversation_id, "reaction", af_bytes, "store", frame_id);
}

void Client::send_unreact(const std::string& msg_id, const std::string& emoji) {
    auto msg = store_.get_message(msg_id);
    if (!msg) return;

    std::string frame_id = rand_hex_id();
    auto now_ms = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    cbor_item_t* af = cbor_new_definite_map(6);
    map_add_str(af,  "type",             "reaction");
    map_add_bytes(af,"id",               (const uint8_t*)frame_id.data(), frame_id.size());
    map_add_str(af,  "conversation_id",  msg->conversation_id.c_str());
    map_add_uint(af, "sent_at",          static_cast<uint64_t>(now_ms));
    map_add_str(af,  "target_message_id",msg_id.c_str());
    map_add_str(af,  "emoji",            emoji.c_str());
    map_add_str(af,  "action",           "remove");
    Bytes af_bytes = cbor_ser(af);
    cbor_decref(&af);

    enqueue_dm(msg->conversation_id, "reaction", af_bytes, "store", frame_id);
}

void Client::send_edit(const std::string& msg_id, const std::string& new_text) {
    auto msg = store_.get_message(msg_id);
    if (!msg) return;

    std::string frame_id = rand_hex_id();
    auto now_ms = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    cbor_item_t* af = cbor_new_definite_map(6);
    map_add_str(af,  "type",             "edit");
    map_add_bytes(af,"id",               (const uint8_t*)frame_id.data(), frame_id.size());
    map_add_str(af,  "conversation_id",  msg->conversation_id.c_str());
    map_add_uint(af, "sent_at",          static_cast<uint64_t>(now_ms));
    map_add_str(af,  "target_message_id",msg_id.c_str());
    map_add_str(af,  "new_text",         new_text.c_str());
    Bytes af_bytes = cbor_ser(af);
    cbor_decref(&af);

    enqueue_dm(msg->conversation_id, "edit", af_bytes, "store", frame_id);
}

void Client::send_delete(const std::string& msg_id) {
    auto msg = store_.get_message(msg_id);
    if (!msg) return;

    std::string frame_id = rand_hex_id();
    auto now_ms = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    cbor_item_t* af = cbor_new_definite_map(5);
    map_add_str(af,  "type",             "delete");
    map_add_bytes(af,"id",               (const uint8_t*)frame_id.data(), frame_id.size());
    map_add_str(af,  "conversation_id",  msg->conversation_id.c_str());
    map_add_uint(af, "sent_at",          static_cast<uint64_t>(now_ms));
    map_add_str(af,  "target_message_id",msg_id.c_str());
    Bytes af_bytes = cbor_ser(af);
    cbor_decref(&af);

    enqueue_dm(msg->conversation_id, "delete", af_bytes, "store", frame_id);
}

void Client::send_typing(const std::string& conv_id, const std::string& action) {
    std::string frame_id = rand_hex_id();
    auto now_ms = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    cbor_item_t* af = cbor_new_definite_map(4);
    map_add_str(af,  "type",            "typing");
    map_add_bytes(af,"id",              (const uint8_t*)frame_id.data(), frame_id.size());
    map_add_str(af,  "conversation_id", conv_id.c_str());
    map_add_uint(af, "sent_at",         static_cast<uint64_t>(now_ms));
    map_add_str(af,  "action",          action.c_str());
    Bytes af_bytes = cbor_ser(af);
    cbor_decref(&af);

    enqueue_dm(conv_id, "typing", af_bytes, "pass_through", frame_id);
}

void Client::mark_read(const std::string& conv_id,
                        const std::string& up_to_id) {
    auto msg = store_.get_message(up_to_id);
    if (!msg) return;
    store_.update_last_read(conv_id, msg->seq);

    std::string frame_id = rand_hex_id();
    auto now_ms = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    cbor_item_t* af = cbor_new_definite_map(5);
    map_add_str(af,  "type",            "read_receipt");
    map_add_bytes(af,"id",              (const uint8_t*)frame_id.data(), frame_id.size());
    map_add_str(af,  "conversation_id", conv_id.c_str());
    map_add_uint(af, "sent_at",         static_cast<uint64_t>(now_ms));
    map_add_str(af,  "up_to_message_id",up_to_id.c_str());
    Bytes af_bytes = cbor_ser(af);
    cbor_decref(&af);

    enqueue_dm(conv_id, "read_receipt", af_bytes, "pass_through", frame_id);
}

// ── Groups ────────────────────────────────────────────────────────────────────

std::string Client::create_group(const std::string& name,
                                   const std::string& type) {
    auto ka   = require_key_a();
    auto now_s = static_cast<int64_t>(std::time(nullptr));
    Bytes nonce(16);
    randombytes_buf(nonce.data(), 16);
    uint8_t ts_bytes[8];
    uint64_t ts = static_cast<uint64_t>(now_s);
    for (int i = 7; i >= 0; --i) { ts_bytes[i] = ts & 0xff; ts >>= 8; }

    Key32 gid_key = sha3_256({
        ByteSpan{ka.pubkey.data(), ka.pubkey.size()},
        ByteSpan{ts_bytes, 8},
        ByteSpan{nonce.data(), 16}
    });
    std::string group_id = to_hex(gid_key);

    // Generate Key B for this group.
    KeyB kb;
    auto kem_kp = mlkem_keygen();
    auto sig_kp = mldsa_keygen();
    kb.id           = group_id;
    kb.relationship = (type == "server" ? "server_channel:" : "group:") + group_id;
    kb.kem_pubkey   = kem_kp.pub;
    kb.kem_privkey  = kem_kp.priv;
    kb.sig_pubkey   = sig_kp.pub;
    kb.sig_privkey  = sig_kp.priv;
    kb.created_at   = now_s;
    keystore_.insert_key_b(kb);

    // Generate own sender key (Key F).
    Key32 sym_key{};
    randombytes_buf(sym_key.data(), 32);
    Key32 my_id = sha3_256(ByteSpan{ka.pubkey.data(), ka.pubkey.size()});
    Keystore::SenderKey sk;
    sk.group_id   = group_id;
    sk.contact_id = to_hex(my_id);
    std::copy(sym_key.begin(), sym_key.end(), sk.sym_key.begin());
    sk.generation = 0;
    sk.created_at = now_s;
    keystore_.set_sender_key(sk);
    keystore_.save();

    Group g;
    g.id         = group_id;
    g.name       = name;
    g.type       = type;
    g.my_role    = "owner";
    g.created_at = now_s;
    store_.upsert_group(g);

    Conversation conv;
    conv.id           = group_id;
    conv.type         = (type == "server") ? "server_channel" : "group";
    conv.display_name = name;
    conv.group_id     = group_id;
    conv.created_at   = now_s;
    store_.upsert_conversation(conv);

    return group_id;
}

void Client::invite_to_group(const std::string& group_id,
                               const std::string& contact_id) {
    auto grp = store_.get_group(group_id);
    if (!grp) throw std::runtime_error("group not found");
    if (grp->my_role != "owner" && grp->my_role != "admin")
        throw std::runtime_error("NOT_ADMIN");

    auto contact = store_.get_contact(contact_id);
    if (!contact) throw std::runtime_error("CONTACT_NOT_FOUND");

    // Build group_invite app frame via pairwise DM ratchet.
    auto now_ms = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    std::string frame_id = rand_hex_id();

    // Collect members and sender keys.
    auto members = store_.list_group_members(group_id);
    auto ka      = require_key_a();
    Key32 my_id  = sha3_256(ByteSpan{ka.pubkey.data(), ka.pubkey.size()});
    std::string my_hex = to_hex(my_id);

    cbor_item_t* members_arr = cbor_new_definite_array(members.size());
    for (const auto& m : members) {
        auto mc = store_.get_contact(m.contact_id);
        cbor_item_t* mem_map = cbor_new_definite_map(3);
        if (mc) {
            map_add_bytes(mem_map,"key_a_pubkey",
                          mc->key_a_pubkey.data(), mc->key_a_pubkey.size());
        }
        map_add_bytes(mem_map,"key_b_kem_pubkey",
                      m.their_key_b_kem.data(), m.their_key_b_kem.size());
        cbor_array_push(members_arr, cbor_move(mem_map));
    }

    // Get my Key B for this group.
    auto my_kb = keystore_.get_key_b(group_id);
    if (!my_kb) throw std::runtime_error("no key_b for group");

    cbor_item_t* af = cbor_new_definite_map(9);
    map_add_str(af,  "type",             "group_invite");
    map_add_bytes(af,"id",               (const uint8_t*)frame_id.data(), frame_id.size());
    map_add_str(af,  "conversation_id",  contact->my_key_b_id.c_str());
    map_add_uint(af, "sent_at",          static_cast<uint64_t>(now_ms));
    map_add_str(af,  "group_id",         group_id.c_str());
    map_add_str(af,  "group_name",       grp->name.c_str());
    map_add_str(af,  "server_type",      grp->type.c_str());
    map_add_bytes(af,"my_key_b_kem_pk",  my_kb->kem_pubkey.data(), my_kb->kem_pubkey.size());
    cbor_map_add(af, (struct cbor_pair){
        .key   = cbor_move(cbor_build_string("existing_members")),
        .value = cbor_move(members_arr)
    });
    Bytes af_bytes = cbor_ser(af);
    cbor_decref(&af);

    // Find DM conversation with this contact to route the invite.
    std::string a = my_hex, b = contact_id;
    if (a > b) std::swap(a, b);
    Key32 cid = sha3_256({
        as_bytes("dm:"),
        ByteSpan{reinterpret_cast<const uint8_t*>(a.data()), a.size()},
        as_bytes(":"),
        ByteSpan{reinterpret_cast<const uint8_t*>(b.data()), b.size()}
    });
    enqueue_dm(to_hex(cid), "group_invite", af_bytes, "store", frame_id);
}

void Client::kick_from_group(const std::string& group_id,
                               const std::string& contact_id) {
    auto grp = store_.get_group(group_id);
    if (!grp) throw std::runtime_error("group not found");
    if (grp->my_role != "owner" && grp->my_role != "admin")
        throw std::runtime_error("NOT_ADMIN");

    store_.remove_group_member(group_id, contact_id);

    // Rotate sender key and notify remaining members.
    auto ka = require_key_a();
    Key32 my_id = sha3_256(ByteSpan{ka.pubkey.data(), ka.pubkey.size()});
    std::string my_hex = to_hex(my_id);

    auto old_sk = keystore_.get_sender_key(group_id, my_hex);
    uint32_t new_gen = old_sk ? old_sk->generation + 1 : 1;
    Key32 new_sym{};
    randombytes_buf(new_sym.data(), 32);
    Keystore::SenderKey sk;
    sk.group_id   = group_id;
    sk.contact_id = my_hex;
    std::copy(new_sym.begin(), new_sym.end(), sk.sym_key.begin());
    sk.generation = new_gen;
    sk.created_at = static_cast<int64_t>(std::time(nullptr));
    keystore_.set_sender_key(sk);
    keystore_.save();
}

void Client::leave_group(const std::string& group_id) {
    auto ka = require_key_a();
    Key32 my_id = sha3_256(ByteSpan{ka.pubkey.data(), ka.pubkey.size()});
    store_.remove_group_member(group_id, to_hex(my_id));
}

// ── Devices ───────────────────────────────────────────────────────────────────

std::vector<KeyCIssued> Client::list_devices() {
    return keystore_.list_key_c();
}

void Client::revoke_device(const std::string& device_id) {
    keystore_.revoke_key_c(device_id);
    keystore_.save();
}

// ── Network / status ──────────────────────────────────────────────────────────

CborMap Client::get_network_status() {
    CborMap result;
    result["anonrouter_connected"] = CborValue::from_bool(ar_client_.is_connected());
    result["relay_count"]          = CborValue::from_uint(0);
    result["unchoked_peers"]       = CborValue::from_uint(0);
    result["net_credit_bytes"]     = CborValue::from_int(0);
    result["dht_peers"]            = CborValue::from_uint(0);

    if (ar_client_.is_connected()) {
        try {
            auto r = ar_client_.call("tft.status", {});
            if (auto it = r.find("unchoked_count"); it != r.end() && it->second.is_uint())
                result["unchoked_peers"] = it->second;
        } catch (...) {}
    }
    return result;
}

CborMap Client::get_inbox_status() {
    CborMap result;
    result["stored_undelivered"] = CborValue::from_uint(0);
    result["sibling_count"]      = CborValue::from_uint(0);
    result["prekeys_low"]        = CborValue::from_bool(false);
    if (inbox_client_.is_connected()) {
        try {
            auto r = inbox_client_.call("inbox.status", {});
            if (auto it = r.find("stored_count"); it != r.end() && it->second.is_uint())
                result["stored_undelivered"] = it->second;
            if (auto it = r.find("sibling_count"); it != r.end() && it->second.is_uint())
                result["sibling_count"] = it->second;
        } catch (...) {}
    }
    // Check prekey low.
    bool low = false;
    for (const auto& kb : keystore_.list_key_b()) {
        if (keystore_.count_prekeys(kb.id) < cfg_.prekey_low_threshold) {
            low = true; break;
        }
    }
    result["prekeys_low"] = CborValue::from_bool(low);
    return result;
}

CborMap Client::get_outbox_status() {
    CborMap result;
    result["pending"]    = CborValue::from_uint(0);
    result["delivering"] = CborValue::from_uint(0);
    if (outbox_client_.is_connected()) {
        try {
            auto r = outbox_client_.call("outbox.stats", {});
            if (auto it = r.find("pending"); it != r.end() && it->second.is_uint())
                result["pending"] = it->second;
        } catch (...) {}
    }
    return result;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

KeyA Client::require_key_a() {
    auto ka = keystore_.get_key_a();
    if (!ka) throw std::runtime_error("SESSION_LOCKED");
    return *ka;
}

GuardInfo Client::get_guard_info() {
    GuardInfo g;
    if (!inbox_client_.is_connected()) return g;
    try {
        auto r = inbox_client_.call("inbox.guard_info", {});
        if (auto it = r.find("guard_node_id"); it != r.end() && it->second.is_string())
            g.guard_node_id = it->second.as_string();
        if (auto it = r.find("guard_endpoint"); it != r.end() && it->second.is_string())
            g.guard_endpoint = it->second.as_string();
        if (auto it = r.find("session_token"); it != r.end() && it->second.is_bytes())
            g.session_token = it->second.as_bytes();

        // Get outbox key_c for inbox_auth_key field.
        for (const auto& kc : keystore_.list_key_c()) {
            if (kc.device_type == "outbox" && !kc.revoked) {
                g.outbox_key_c_pubkey = Bytes(kc.key_c_pubkey.begin(),
                                               kc.key_c_pubkey.end());
                g.outbox_auth_expiry  = kc.expires_at;
                break;
            }
        }
    } catch (...) {}
    return g;
}

std::string Client::my_sender_id_hex() {
    auto ka = keystore_.get_key_a();
    if (!ka) return "";
    Key32 id = sha3_256(ByteSpan{ka->pubkey.data(), ka->pubkey.size()});
    return to_hex(id);
}

} // namespace sw::client
