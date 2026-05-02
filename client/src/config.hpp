#pragma once
#include <string>

namespace sw::client {

struct Config {
    std::string keystore_path    = "keystore.dat";
    std::string keystore_salt    = "keystore.salt";
    std::string messages_db_path = "messages.db";
    std::string client_sock      = "/run/scatterweb/client.sock";
    std::string anonrouter_sock  = "/run/anonrouter/daemon.sock";
    std::string inbox_sock       = "/run/scatterweb/inbox.sock";
    std::string outbox_sock      = "/run/scatterweb/outbox.sock";

    int dht_refresh_interval_s         = 1800;
    int key_c_renewal_threshold_days   = 7;
    int max_skipped_msg_keys           = 100;
    int prekey_low_threshold           = 5;
    int prekey_batch_size              = 20;

    static Config load(const std::string& path);
};

} // namespace sw::client
