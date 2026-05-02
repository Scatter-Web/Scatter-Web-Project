#include <sw/ipc/client.hpp>
#include <sw/ipc/codec.hpp>
#include <sw/types.hpp>

#include <atomic>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <vector>

using namespace sw::ipc;

static const char* DEFAULT_SOCKET_PATH = "/run/scatterweb/client.sock";

static std::string g_socket_path;

static void init_socket_path() {
    const char* env = std::getenv("SW_SOCKET_PATH");
    g_socket_path = env ? env : DEFAULT_SOCKET_PATH;
}

static std::string format_time_ms(uint64_t ms) {
    time_t t = static_cast<time_t>(ms / 1000);
    char buf[32];
    struct tm tm_info{};
    localtime_r(&t, &tm_info);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tm_info);
    return buf;
}

static std::string read_passphrase(const char* prompt) {
    std::cerr << prompt << std::flush;
    struct termios old{}, cur{};
    tcgetattr(STDIN_FILENO, &old);
    cur = old;
    cur.c_lflag &= ~(tcflag_t)(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &cur);
    std::string pass;
    std::getline(std::cin, pass);
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    std::cerr << "\n";
    return pass;
}

// ── CborMap helpers ───────────────────────────────────────────────────────────

static std::string get_str(const CborMap& m, const std::string& k,
                            const std::string& def = "") {
    auto it = m.find(k);
    if (it != m.end() && it->second.is_string()) return it->second.as_string();
    return def;
}

static uint64_t get_uint(const CborMap& m, const std::string& k, uint64_t def = 0) {
    auto it = m.find(k);
    if (it != m.end() && it->second.is_uint()) return it->second.as_uint();
    return def;
}

static int64_t get_int(const CborMap& m, const std::string& k, int64_t def = 0) {
    auto it = m.find(k);
    if (it == m.end()) return def;
    if (it->second.is_int())  return it->second.as_int();
    if (it->second.is_uint()) return static_cast<int64_t>(it->second.as_uint());
    return def;
}

static bool get_bool(const CborMap& m, const std::string& k, bool def = false) {
    auto it = m.find(k);
    if (it != m.end() && it->second.is_bool()) return it->second.as_bool();
    return def;
}

// ── Call wrapper ──────────────────────────────────────────────────────────────

static CborMap xcall(Client& c, const std::string& method,
                     const CborMap& params = {}) {
    try {
        return c.call(method, params, "sw-cli");
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        std::exit(1);
    }
}

// ── Session ───────────────────────────────────────────────────────────────────

static void cmd_unlock(Client& c) {
    auto pass = read_passphrase("Passphrase: ");
    CborMap p;
    p["passphrase"] = CborValue::from_string(pass);
    auto r = xcall(c, "session.unlock", p);
    std::cout << "Unlocked\n"
              << "  Name:        " << get_str(r, "display_name") << "\n"
              << "  Fingerprint: " << get_str(r, "key_a_pubkey_fingerprint") << "\n";
}

static void cmd_lock(Client& c) {
    xcall(c, "session.lock");
    std::cout << "Locked\n";
}

// ── Identity ──────────────────────────────────────────────────────────────────

static void cmd_id(Client& c) {
    auto r = xcall(c, "identity.get_profile");
    std::cout << "Name:         " << get_str(r, "display_name") << "\n"
              << "Fingerprint:  " << get_str(r, "key_a_fingerprint") << "\n"
              << "Contact card: " << get_str(r, "contact_card_uri") << "\n";
}

static void cmd_id_set_name(Client& c, const std::string& name) {
    CborMap p;
    p["display_name"] = CborValue::from_string(name);
    xcall(c, "identity.set_display_name", p);
    std::cout << "Name updated\n";
}

// identity.get_contact_card_qr returns PNG bytes; the CLI prints the URI as a
// fallback since rendering a PNG as ASCII art requires an external library.
static void cmd_id_qr(Client& c) {
    auto r = xcall(c, "identity.get_profile");
    std::cout << "Contact card URI:\n" << get_str(r, "contact_card_uri") << "\n"
              << "(QR PNG rendering not available in CLI reference implementation)\n";
}

// ── Contacts ──────────────────────────────────────────────────────────────────

static void cmd_contacts_list(Client& c) {
    auto r = xcall(c, "contacts.list");
    auto it = r.find("contacts");
    if (it == r.end() || !it->second.is_array()) { std::cout << "No contacts\n"; return; }
    for (const auto& v : it->second.as_array()) {
        const auto& m = v.as_map();
        std::cout << get_str(m, "id") << "  "
                  << std::left << std::setw(24) << get_str(m, "display_name")
                  << "  " << get_str(m, "status") << "\n";
    }
}

static void cmd_contacts_add(Client& c, const std::string& uri) {
    CborMap p;
    p["contact_card_uri"] = CborValue::from_string(uri);
    auto r = xcall(c, "contacts.send_request", p);
    std::cout << "Request sent\n"
              << "  ID:   " << get_str(r, "contact_id") << "\n"
              << "  Name: " << get_str(r, "display_name") << "\n";
}

static void cmd_contacts_simple(Client& c, const std::string& method,
                                 const std::string& id) {
    CborMap p;
    p["contact_id"] = CborValue::from_string(id);
    xcall(c, method, p);
    std::cout << "Done\n";
}

// ── Conversations ─────────────────────────────────────────────────────────────

static void cmd_convs_list(Client& c) {
    auto r = xcall(c, "conversations.list");
    auto it = r.find("conversations");
    if (it == r.end() || !it->second.is_array()) { std::cout << "No conversations\n"; return; }
    for (const auto& v : it->second.as_array()) {
        const auto& m = v.as_map();
        std::string preview = "(empty)";
        auto lm_it = m.find("last_message");
        if (lm_it != m.end() && lm_it->second.is_map()) {
            const auto& lm = lm_it->second.as_map();
            std::string tp = get_str(lm, "text_preview");
            if (!tp.empty()) preview = tp.substr(0, 40);
        }
        std::cout << get_str(m, "id") << "  "
                  << std::left << std::setw(20) << get_str(m, "display_name")
                  << "  " << std::setw(14) << get_str(m, "type")
                  << "  unread:" << std::setw(4) << get_uint(m, "unread_count")
                  << "  " << preview << "\n";
    }
}

// ── Messages ──────────────────────────────────────────────────────────────────

static void print_message(const CborMap& msg) {
    std::string sender = get_str(msg, "sender_name");
    if (sender.empty()) {
        auto id = get_str(msg, "sender_id");
        sender = id.size() > 8 ? id.substr(0, 8) + "…" : id;
    }
    uint64_t ts = get_uint(msg, "sent_at");
    std::string text = get_str(msg, "text");
    std::string status = get_str(msg, "status");
    std::cout << "[" << format_time_ms(ts) << "] "
              << std::left << std::setw(16) << sender;
    if (!text.empty()) std::cout << text;
    else std::cout << "(attachment)";
    if (!status.empty() && status != "delivered") std::cout << "  [" << status << "]";
    std::cout << "\n";
}

static void cmd_history(Client& c, const std::string& conv_id, uint32_t limit = 20) {
    CborMap p;
    p["conversation_id"] = CborValue::from_string(conv_id);
    p["before_id"]       = CborValue::null_val();
    p["limit"]           = CborValue::from_uint(limit);
    auto r = xcall(c, "messages.get", p);
    auto it = r.find("messages");
    if (it == r.end() || !it->second.is_array()) { std::cout << "No messages\n"; return; }
    const auto& arr = it->second.as_array();
    // API returns reverse chronological — print oldest first
    for (int i = (int)arr.size() - 1; i >= 0; --i)
        print_message(arr[i].as_map());
}

static void cmd_msg_interactive(Client& c, const std::string& conv_id) {
    std::cout << "=== " << conv_id << " — /quit to exit ===\n";
    cmd_history(c, conv_id, 20);

    // Push events arrive on the receive thread; use a mutex only for stdout.
    std::mutex out_mu;
    c.on_push([&](const std::string& ev, const CborMap& payload) {
        if (ev != "message.received") return;
        if (get_str(payload, "conversation_id") != conv_id) return;
        std::lock_guard<std::mutex> lk(out_mu);
        std::cout << "\r[" << get_str(payload, "sender_name")
                  << "] " << get_str(payload, "text_preview") << "\n> " << std::flush;
    });

    std::string line;
    while (true) {
        {
            std::lock_guard<std::mutex> lk(out_mu);
            std::cout << "> " << std::flush;
        }
        if (!std::getline(std::cin, line)) break;
        if (line == "/quit") break;
        if (line.empty()) continue;

        CborMap p;
        p["conversation_id"] = CborValue::from_string(conv_id);
        p["text"]            = CborValue::from_string(line);
        p["attachments"]     = CborValue::from_array({});
        p["reply_to_id"]     = CborValue::null_val();
        p["mentions"]        = CborValue::from_array({});
        // xcall without out_mu held — avoids deadlock with receive thread push handler
        xcall(c, "messages.send", p);
    }
}

static void cmd_send(Client& c, const std::string& conv_id,
                     const std::string& text) {
    CborMap p;
    p["conversation_id"] = CborValue::from_string(conv_id);
    p["text"]            = CborValue::from_string(text);
    p["attachments"]     = CborValue::from_array({});
    p["reply_to_id"]     = CborValue::null_val();
    p["mentions"]        = CborValue::from_array({});
    auto r = xcall(c, "messages.send", p);
    std::cout << "Sent: " << get_str(r, "message_id") << "\n";
}

static void cmd_send_file(Client& c, const std::string& conv_id,
                           const std::string& filepath) {
    std::ifstream f(filepath, std::ios::binary);
    if (!f) { std::cerr << "Cannot open: " << filepath << "\n"; std::exit(1); }
    sw::Bytes data((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());

    std::string filename = filepath;
    auto slash = filepath.rfind('/');
    if (slash != std::string::npos) filename = filepath.substr(slash + 1);

    CborMap att;
    att["filename"]  = CborValue::from_string(filename);
    att["mime_type"] = CborValue::from_string("application/octet-stream");
    att["data"]      = CborValue::from_bytes(data);

    CborMap p;
    p["conversation_id"] = CborValue::from_string(conv_id);
    p["text"]            = CborValue::null_val();
    p["attachments"]     = CborValue::from_array({CborValue::from_map(att)});
    p["reply_to_id"]     = CborValue::null_val();
    p["mentions"]        = CborValue::from_array({});
    auto r = xcall(c, "messages.send", p);
    std::cout << "Sent: " << get_str(r, "message_id") << "\n";
}

static void cmd_react(Client& c, const std::string& msg_id,
                       const std::string& emoji) {
    CborMap p;
    p["message_id"] = CborValue::from_string(msg_id);
    p["emoji"]      = CborValue::from_string(emoji);
    xcall(c, "messages.react", p);
    std::cout << "Reacted\n";
}

static void cmd_delete(Client& c, const std::string& msg_id) {
    CborMap p;
    p["message_id"] = CborValue::from_string(msg_id);
    xcall(c, "messages.delete", p);
    std::cout << "Deleted\n";
}

// ── Groups & Servers ──────────────────────────────────────────────────────────

static void cmd_group_create(Client& c, const std::string& name,
                              const std::string& type = "group") {
    CborMap p;
    p["name"] = CborValue::from_string(name);
    p["type"] = CborValue::from_string(type);
    auto r = xcall(c, "groups.create", p);
    std::cout << (type == "server" ? "Server" : "Group") << " created\n"
              << "  group_id: " << get_str(r, "group_id") << "\n"
              << "  conv_id:  " << get_str(r, "conversation_id") << "\n";
}

static void cmd_group_invite(Client& c, const std::string& gid,
                              const std::string& cid) {
    CborMap p;
    p["group_id"]   = CborValue::from_string(gid);
    p["contact_id"] = CborValue::from_string(cid);
    xcall(c, "groups.invite", p);
    std::cout << "Invited\n";
}

static void cmd_group_kick(Client& c, const std::string& gid,
                            const std::string& cid) {
    CborMap p;
    p["group_id"]   = CborValue::from_string(gid);
    p["contact_id"] = CborValue::from_string(cid);
    xcall(c, "groups.kick", p);
    std::cout << "Kicked\n";
}

static void cmd_group_leave(Client& c, const std::string& gid) {
    CborMap p;
    p["group_id"] = CborValue::from_string(gid);
    xcall(c, "groups.leave", p);
    std::cout << "Left\n";
}

static void cmd_server_add_channel(Client& c, const std::string& sid,
                                    const std::string& name,
                                    const std::string& type) {
    CborMap p;
    p["server_id"] = CborValue::from_string(sid);
    p["name"]      = CborValue::from_string(name);
    p["type"]      = CborValue::from_string(type);
    auto r = xcall(c, "servers.create_channel", p);
    std::cout << "Channel created\n"
              << "  channel_id: " << get_str(r, "channel_id") << "\n"
              << "  conv_id:    " << get_str(r, "conversation_id") << "\n";
}

static void cmd_server_set_role(Client& c, const std::string& sid,
                                 const std::string& cid,
                                 const std::string& role) {
    CborMap p;
    p["server_id"]  = CborValue::from_string(sid);
    p["contact_id"] = CborValue::from_string(cid);
    p["role"]       = CborValue::from_string(role);
    xcall(c, "servers.set_member_role", p);
    std::cout << "Role updated\n";
}

// ── Calls ─────────────────────────────────────────────────────────────────────

static void cmd_call_start(Client& c, const std::string& conv_id, bool video) {
    CborMap audio_cfg;
    audio_cfg["enabled"] = CborValue::from_bool(true);
    CborMap video_cfg;
    video_cfg["enabled"]    = CborValue::from_bool(video);
    video_cfg["resolution"] = CborValue::from_string("480p");
    CborMap media;
    media["audio"] = CborValue::from_map(audio_cfg);
    media["video"] = CborValue::from_map(video_cfg);

    CborMap p;
    p["conversation_id"] = CborValue::from_string(conv_id);
    p["anon_level"]      = CborValue::from_uint(1);
    p["media_config"]    = CborValue::from_map(media);
    auto r = xcall(c, "calls.start", p);
    std::cout << "Call started: " << get_str(r, "call_id") << "\n";
}

static void cmd_call_accept(Client& c, const std::string& call_id) {
    CborMap p;
    p["call_id"] = CborValue::from_string(call_id);
    xcall(c, "calls.accept", p);
    std::cout << "Call accepted\n";
}

static void cmd_call_end(Client& c, const std::string& call_id) {
    CborMap p;
    p["call_id"] = CborValue::from_string(call_id);
    xcall(c, "calls.end", p);
    std::cout << "Call ended\n";
}

// ── Devices & Status ──────────────────────────────────────────────────────────

static void cmd_devices_list(Client& c) {
    auto r = xcall(c, "devices.list");
    auto it = r.find("devices");
    if (it == r.end() || !it->second.is_array()) { std::cout << "No devices\n"; return; }
    for (const auto& v : it->second.as_array()) {
        const auto& m = v.as_map();
        std::cout << get_str(m, "device_id") << "  "
                  << std::left << std::setw(8) << get_str(m, "type")
                  << "  " << get_str(m, "label")
                  << (get_bool(m, "revoked") ? "  [revoked]" : "") << "\n";
    }
}

static void cmd_devices_revoke(Client& c, const std::string& dev_id) {
    CborMap p;
    p["device_id"] = CborValue::from_string(dev_id);
    xcall(c, "devices.revoke", p);
    std::cout << "Revoked\n";
}

static void cmd_status(Client& c) {
    auto nr   = xcall(c, "network.get_status");
    auto ir   = xcall(c, "devices.get_inbox_status");
    auto outr = xcall(c, "devices.get_outbox_status");

    std::cout << "Network:\n"
              << "  AnonRouter: "
              << (get_bool(nr, "anonrouter_connected") ? "connected" : "disconnected") << "\n"
              << "  Relays:     " << get_uint(nr, "relay_count") << "\n"
              << "  DHT peers:  " << get_uint(nr, "dht_peers") << "\n"
              << "  TFT credit: " << get_int(nr, "net_credit_bytes") << " bytes\n"
              << "Inbox:\n"
              << "  Stored:     " << get_uint(ir, "stored_undelivered") << "\n"
              << "  Prekeys low:" << (get_bool(ir, "prekeys_low") ? " YES" : " no") << "\n"
              << "Outbox:\n"
              << "  Pending:    " << get_uint(outr, "pending") << "\n"
              << "  Delivering: " << get_uint(outr, "delivering") << "\n";
}

// ── Shell (interactive REPL with push events) ─────────────────────────────────

static void cmd_shell(Client& c) {
    std::cout << "=== ScatterWeb shell — Ctrl+C or 'quit' to exit ===\n";

    std::mutex out_mu;
    c.on_push([&](const std::string& ev, const CborMap& payload) {
        std::lock_guard<std::mutex> lk(out_mu);
        std::cout << "[" << ev << "]";
        for (const auto& [k, v] : payload) {
            std::cout << " " << k << "=";
            if (v.is_string())      std::cout << v.as_string();
            else if (v.is_uint())   std::cout << v.as_uint();
            else if (v.is_int())    std::cout << v.as_int();
            else if (v.is_bool())   std::cout << (v.as_bool() ? "true" : "false");
            else                    std::cout << "…";
        }
        std::cout << "\n> " << std::flush;
    });

    std::string line;
    while (true) {
        {
            std::lock_guard<std::mutex> lk(out_mu);
            std::cout << "> " << std::flush;
        }
        if (!std::getline(std::cin, line)) break;
        if (line == "quit" || line == "exit") break;
        if (!line.empty()) {
            std::lock_guard<std::mutex> lk(out_mu);
            std::cout << "(use 'sw <command>' from a separate terminal; "
                         "this shell only shows push events)\n";
        }
    }
}

// ── Help ──────────────────────────────────────────────────────────────────────

static void usage() {
    std::cout <<
        "Usage: sw <command> [args]\n"
        "\n"
        "Session:\n"
        "  sw unlock\n"
        "  sw lock\n"
        "\n"
        "Identity:\n"
        "  sw id\n"
        "  sw id set-name <name>\n"
        "  sw id qr\n"
        "\n"
        "Contacts:\n"
        "  sw contacts list\n"
        "  sw contacts add <contact_card_uri>\n"
        "  sw contacts accept <contact_id>\n"
        "  sw contacts decline <contact_id>\n"
        "  sw contacts block <contact_id>\n"
        "\n"
        "Conversations & Messages:\n"
        "  sw convs list\n"
        "  sw msg <conversation_id>                  interactive mode\n"
        "  sw send <conversation_id> <text>\n"
        "  sw send <conversation_id> --file <path>\n"
        "  sw history <conversation_id> [--limit N]\n"
        "  sw react <message_id> <emoji>\n"
        "  sw delete <message_id>\n"
        "\n"
        "Groups & Servers:\n"
        "  sw group create <name>\n"
        "  sw group invite <group_id> <contact_id>\n"
        "  sw group kick <group_id> <contact_id>\n"
        "  sw group leave <group_id>\n"
        "  sw server create <name>\n"
        "  sw server add-channel <server_id> <name> <text|voice|video>\n"
        "  sw server set-role <server_id> <contact_id> <admin|member>\n"
        "\n"
        "Calls:\n"
        "  sw call <conversation_id> [--video]\n"
        "  sw call accept <call_id>\n"
        "  sw call end <call_id>\n"
        "\n"
        "Devices & Status:\n"
        "  sw devices list\n"
        "  sw devices revoke <device_id>\n"
        "  sw status\n"
        "\n"
        "Interactive:\n"
        "  sw shell                                  REPL with live push events\n"
        "\n"
        "Environment:\n"
        "  SW_SOCKET_PATH  Override socket path "
        "(default: /run/scatterweb/client.sock)\n";
}

// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    init_socket_path();

    if (argc < 2 || std::string(argv[1]) == "--help" ||
                    std::string(argv[1]) == "-h"     ||
                    std::string(argv[1]) == "help") {
        usage();
        return argc < 2 ? 1 : 0;
    }

    Client c(g_socket_path);
    try {
        c.connect();
    } catch (const std::exception& e) {
        std::cerr << "Cannot connect to " << g_socket_path
                  << ": " << e.what() << "\n"
                  << "Is sw-client running?\n";
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "unlock") {
        cmd_unlock(c);

    } else if (cmd == "lock") {
        cmd_lock(c);

    } else if (cmd == "id") {
        if (argc == 2) {
            cmd_id(c);
        } else if (argc >= 4 && std::string(argv[2]) == "set-name") {
            cmd_id_set_name(c, argv[3]);
        } else if (argc >= 3 && std::string(argv[2]) == "qr") {
            cmd_id_qr(c);
        } else {
            usage(); return 1;
        }

    } else if (cmd == "contacts") {
        if (argc < 3) { usage(); return 1; }
        std::string sub = argv[2];
        if      (sub == "list")                    cmd_contacts_list(c);
        else if (sub == "add"     && argc >= 4)    cmd_contacts_add(c, argv[3]);
        else if (sub == "accept"  && argc >= 4)    cmd_contacts_simple(c, "contacts.accept_request", argv[3]);
        else if (sub == "decline" && argc >= 4)    cmd_contacts_simple(c, "contacts.decline_request", argv[3]);
        else if (sub == "block"   && argc >= 4)    cmd_contacts_simple(c, "contacts.block", argv[3]);
        else { usage(); return 1; }

    } else if (cmd == "convs") {
        if (argc >= 3 && std::string(argv[2]) == "list") cmd_convs_list(c);
        else { usage(); return 1; }

    } else if (cmd == "msg") {
        if (argc < 3) { usage(); return 1; }
        cmd_msg_interactive(c, argv[2]);

    } else if (cmd == "send") {
        if (argc < 4) { usage(); return 1; }
        if (std::string(argv[3]) == "--file" && argc >= 5) {
            cmd_send_file(c, argv[2], argv[4]);
        } else {
            std::string text = argv[3];
            for (int i = 4; i < argc; ++i) { text += ' '; text += argv[i]; }
            cmd_send(c, argv[2], text);
        }

    } else if (cmd == "history") {
        if (argc < 3) { usage(); return 1; }
        uint32_t limit = 20;
        for (int i = 3; i + 1 < argc; ++i)
            if (std::string(argv[i]) == "--limit") limit = (uint32_t)std::stoul(argv[i+1]);
        cmd_history(c, argv[2], limit);

    } else if (cmd == "react") {
        if (argc < 4) { usage(); return 1; }
        cmd_react(c, argv[2], argv[3]);

    } else if (cmd == "delete") {
        if (argc < 3) { usage(); return 1; }
        cmd_delete(c, argv[2]);

    } else if (cmd == "group") {
        if (argc < 3) { usage(); return 1; }
        std::string sub = argv[2];
        if      (sub == "create" && argc >= 4) cmd_group_create(c, argv[3]);
        else if (sub == "invite" && argc >= 5) cmd_group_invite(c, argv[3], argv[4]);
        else if (sub == "kick"   && argc >= 5) cmd_group_kick(c, argv[3], argv[4]);
        else if (sub == "leave"  && argc >= 4) cmd_group_leave(c, argv[3]);
        else { usage(); return 1; }

    } else if (cmd == "server") {
        if (argc < 3) { usage(); return 1; }
        std::string sub = argv[2];
        if      (sub == "create"      && argc >= 4) cmd_group_create(c, argv[3], "server");
        else if (sub == "add-channel" && argc >= 6) cmd_server_add_channel(c, argv[3], argv[4], argv[5]);
        else if (sub == "set-role"    && argc >= 6) cmd_server_set_role(c, argv[3], argv[4], argv[5]);
        else { usage(); return 1; }

    } else if (cmd == "call") {
        if (argc < 3) { usage(); return 1; }
        std::string sub = argv[2];
        if (sub == "accept" && argc >= 4) {
            cmd_call_accept(c, argv[3]);
        } else if (sub == "end" && argc >= 4) {
            cmd_call_end(c, argv[3]);
        } else {
            bool video = false;
            for (int i = 3; i < argc; ++i)
                if (std::string(argv[i]) == "--video") video = true;
            cmd_call_start(c, sub, video);
        }

    } else if (cmd == "devices") {
        if (argc < 3) { usage(); return 1; }
        std::string sub = argv[2];
        if      (sub == "list")                  cmd_devices_list(c);
        else if (sub == "revoke" && argc >= 4)   cmd_devices_revoke(c, argv[3]);
        else { usage(); return 1; }

    } else if (cmd == "status") {
        cmd_status(c);

    } else if (cmd == "shell") {
        cmd_shell(c);

    } else {
        std::cerr << "Unknown command: " << cmd << "\n";
        usage();
        return 1;
    }

    return 0;
}
