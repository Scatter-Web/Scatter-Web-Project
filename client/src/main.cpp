#include "config.hpp"
#include "client.hpp"
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>

static sw::client::Client* g_client = nullptr;

static void handle_signal(int) {
    if (g_client) g_client->stop();
}

int main(int argc, char** argv) {
    std::string config_path = "/etc/scatterweb/client.conf";
    if (argc >= 2) config_path = argv[1];

    sw::client::Config cfg;
    if (std::filesystem::exists(config_path)) {
        try {
            cfg = sw::client::Config::load(config_path);
        } catch (const std::exception& e) {
            std::cerr << "[client] config error: " << e.what() << "\n";
            return EXIT_FAILURE;
        }
    } else {
        std::cerr << "[client] config not found at " << config_path
                  << ", using defaults\n";
    }

    std::error_code ec;
    std::filesystem::create_directories(
        std::filesystem::path(cfg.messages_db_path).parent_path(), ec);

    sw::client::Client client(cfg);
    g_client = &client;

    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);

    try {
        client.start();
    } catch (const std::exception& e) {
        std::cerr << "[client] fatal: " << e.what() << "\n";
        return EXIT_FAILURE;
    }

    client.wait();
    return EXIT_SUCCESS;
}
