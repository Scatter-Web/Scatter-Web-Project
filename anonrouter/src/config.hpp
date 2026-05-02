#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

namespace sw::anonrouter {

struct Config {
    std::string listen_addr  = "0.0.0.0:9000";
    std::string ipc_path     = "/run/anonrouter/daemon.sock";
    std::string run_dir      = "/var/lib/anonrouter";
    std::string node_role    = "full";  // bootstrap | full | observer
    std::string log_level    = "info";

    std::vector<std::string> bootstrap_nodes;

    struct Tft {
        size_t   max_guard_slots   = 20;
        double   max_fwd_bw_frac   = 0.20;   // fraction of uplink
        uint32_t round_seconds     = 30;
        int64_t  max_debt_bytes    = 52'428'800;  // 50 MiB
        int64_t  new_peer_balance  = -10'485'760; // -10 MiB bootstrap debt
        size_t   unchoke_slots     = 19;
        int64_t  opt_unchoke_interval = 3;   // rounds
        int64_t  credit_decay_interval_s = 3600;
        double   credit_decay_factor = 0.99;
        int64_t  credit_prune_min_bytes = 1024;
    } tft;

    struct Anonymity {
        int default_level = 1;
        int max_recruitment_ttl_s = 1800;
        int max_bytes_per_slot_per_min = 5 * 1024 * 1024;
    } anonymity;

    // Minimal key=value parser (no section support needed for first pass).
    // Only handles flat keys; section headers ignored.
    static Config load(const std::string& path) {
        Config c;
        std::ifstream f(path);
        if (!f) throw std::runtime_error("Cannot open config: " + path);

        std::string line;
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#' || line[0] == '[') continue;
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;

            std::string key = trim(line.substr(0, eq));
            std::string val = trim(line.substr(eq + 1));
            // Strip inline comments
            auto hash = val.find('#');
            if (hash != std::string::npos) val = trim(val.substr(0, hash));

            if (key == "listen_addr")        c.listen_addr = val;
            else if (key == "ipc_path")      c.ipc_path    = val;
            else if (key == "run_dir")       c.run_dir     = val;
            else if (key == "node_role")     c.node_role   = val;
            else if (key == "log_level")     c.log_level   = val;
            else if (key == "bootstrap")     c.bootstrap_nodes.push_back(val);
            else if (key == "max_guard_slots")   c.tft.max_guard_slots = std::stoul(val);
            else if (key == "max_fwd_bw_frac")   c.tft.max_fwd_bw_frac = std::stod(val);
            else if (key == "tft_round_seconds")  c.tft.round_seconds   = std::stoul(val);
            else if (key == "max_debt_bytes")      c.tft.max_debt_bytes  = std::stoll(val);
            else if (key == "default_anon_level")  c.anonymity.default_level = std::stoi(val);
        }
        return c;
    }

private:
    static std::string trim(std::string s) {
        size_t a = s.find_first_not_of(" \t\r");
        size_t b = s.find_last_not_of(" \t\r");
        return (a == std::string::npos) ? "" : s.substr(a, b - a + 1);
    }
};

} // namespace sw::anonrouter
