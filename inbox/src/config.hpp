#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#include <fstream>
#include <sstream>

namespace sw::inbox {

struct Config {
    std::string ipc_path          = "/run/scatterweb/inbox.sock";
    std::string anonrouter_path   = "/run/anonrouter/daemon.sock";
    std::string db_path           = "/var/lib/scatterweb/inbox.db";
    int32_t     default_retention_days   = 7;
    int32_t     passthrough_timeout_s    = 60;
    int32_t     cr_guard_rate_limit_hour = 20;  // contact-request guard: max frames/hour
    int32_t     replication_timeout_s    = 30;

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
            auto hash = val.find('#');
            if (hash != std::string::npos) val = trim(val.substr(0, hash));
            if      (key == "ipc_path")           c.ipc_path         = val;
            else if (key == "anonrouter_path")    c.anonrouter_path  = val;
            else if (key == "db_path")            c.db_path          = val;
            else if (key == "default_retention_days") c.default_retention_days = std::stoi(val);
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

} // namespace sw::inbox
