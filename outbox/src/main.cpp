#include "config.hpp"
#include "outbox.hpp"
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>

static sw::outbox::Outbox* g_outbox = nullptr;

static void handle_signal(int) {
    if (g_outbox) g_outbox->stop();
}

int main(int argc, char** argv) {
    std::string config_path = "/etc/scatterweb/outbox.conf";
    if (argc >= 2) config_path = argv[1];

    sw::outbox::Config cfg;
    if (std::filesystem::exists(config_path)) {
        try {
            cfg = sw::outbox::Config::load(config_path);
        } catch (const std::exception& e) {
            std::cerr << "[outbox] config error: " << e.what() << "\n";
            return EXIT_FAILURE;
        }
    } else {
        std::cerr << "[outbox] config not found at " << config_path
                  << ", using defaults\n";
    }

    std::error_code ec;
    std::filesystem::create_directories(
        std::filesystem::path(cfg.db_path).parent_path(), ec);

    sw::outbox::Outbox outbox(cfg);
    g_outbox = &outbox;

    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);

    try {
        outbox.start();
    } catch (const std::exception& e) {
        std::cerr << "[outbox] fatal: " << e.what() << "\n";
        return EXIT_FAILURE;
    }

    outbox.wait();
    return EXIT_SUCCESS;
}
