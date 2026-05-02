#include "config.hpp"
#include <fstream>
#include <stdexcept>
#include <sstream>

namespace sw::client {

Config Config::load(const std::string& path) {
    Config cfg;
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open config: " + path);

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

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
