#include "config.hpp"
#include "inbox.hpp"
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <sodium.h>

static sw::inbox::Inbox* g_inbox = nullptr;

static void handle_signal(int) {
    if (g_inbox) g_inbox->stop();
}

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "[inbox] fatal: libsodium init failed\n";
        return EXIT_FAILURE;
    }

    std::string config_path = "/etc/scatterweb/inbox.conf";
    if (argc >= 2) config_path = argv[1];

    sw::inbox::Config cfg;
    if (std::filesystem::exists(config_path)) {
        try {
            cfg = sw::inbox::Config::load(config_path);
        } catch (const std::exception& e) {
            std::cerr << "[inbox] config error: " << e.what() << "\n";
            return EXIT_FAILURE;
        }
    } else {
        std::cerr << "[inbox] config not found at " << config_path
                  << ", using defaults\n";
    }

    std::error_code ec;
    std::filesystem::create_directories(
        std::filesystem::path(cfg.db_path).parent_path(), ec);

    sw::inbox::Inbox inbox(cfg);
    g_inbox = &inbox;

    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);

    try {
        inbox.start();
    } catch (const std::exception& e) {
        std::cerr << "[inbox] fatal: " << e.what() << "\n";
        return EXIT_FAILURE;
    }

    inbox.wait();
    return EXIT_SUCCESS;
}
