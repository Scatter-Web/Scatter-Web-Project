#include "config.hpp"
#include <fstream>
#include <stdexcept>
#include <sstream>

namespace sw::client {

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

Config Config::load(const std::string& path) {
    Config cfg;
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open config: " + path);

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        auto hash = val.find('#');
        if (hash != std::string::npos) val = trim(val.substr(0, hash));

        if      (key == "keystore_path")    cfg.keystore_path    = val;
        else if (key == "keystore_salt")    cfg.keystore_salt    = val;
        else if (key == "messages_db_path") cfg.messages_db_path = val;
        else if (key == "client_sock")      cfg.client_sock      = val;
        else if (key == "anonrouter_sock")  cfg.anonrouter_sock  = val;
        else if (key == "inbox_sock")       cfg.inbox_sock       = val;
        else if (key == "outbox_sock")      cfg.outbox_sock      = val;
    }
    return cfg;
}

} // namespace sw::client
