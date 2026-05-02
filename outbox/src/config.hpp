#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#include <fstream>

namespace sw::outbox {

struct Config {
    std::string ipc_path           = "/run/scatterweb/outbox.sock";
    std::string anonrouter_path    = "/run/anonrouter/daemon.sock";
    std::string db_path            = "/var/lib/scatterweb/outbox.db";
    int32_t     default_ttl_days   = 7;
    int32_t     retry_window_s     = 600;   // 10 minutes
    int32_t     max_retries        = 3;
    int32_t     replication_timeout_s = 30;

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
            if      (key == "ipc_path")         c.ipc_path         = val;
            else if (key == "anonrouter_path")  c.anonrouter_path  = val;
            else if (key == "db_path")          c.db_path          = val;
            else if (key == "default_ttl_days") c.default_ttl_days = std::stoi(val);
            else if (key == "max_retries")      c.max_retries      = std::stoi(val);
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

} // namespace sw::outbox
