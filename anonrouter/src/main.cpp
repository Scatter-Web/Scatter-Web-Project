#include "config.hpp"
#include "router.hpp"
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

static sw::anonrouter::Router* g_router = nullptr;

static void handle_signal(int) {
    if (g_router) g_router->stop();
}

int main(int argc, char** argv) {
    std::string config_path = "/etc/anonrouter/anonrouter.conf";
    if (argc >= 2) config_path = argv[1];

    sw::anonrouter::Config cfg;
    if (std::filesystem::exists(config_path)) {
        try {
            cfg = sw::anonrouter::Config::load(config_path);
        } catch (const std::exception& e) {
            std::cerr << "[anonrouter] config error: " << e.what() << "\n";
            return EXIT_FAILURE;
        }
    } else {
        std::cerr << "[anonrouter] config not found at " << config_path
                  << ", using defaults\n";
    }

    std::error_code ec;
    std::filesystem::create_directories(cfg.run_dir, ec);

    sw::anonrouter::Router router(cfg);
    g_router = &router;

    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);

    try {
        router.start();
    } catch (const std::exception& e) {
        std::cerr << "[anonrouter] fatal: " << e.what() << "\n";
        return EXIT_FAILURE;
    }

    router.wait();
    return EXIT_SUCCESS;
}
