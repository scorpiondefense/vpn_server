#include "vpn/core/server.hpp"
#include "vpn/core/config.hpp"
#include "vpn/util/logger.hpp"
#include <iostream>
#include <csignal>
#include <cstring>

namespace {

vpn::core::Server* g_server = nullptr;

void signal_handler(int signum) {
    if (g_server) {
        std::cout << "\nReceived signal " << signum << ", shutting down...\n";
        g_server->stop();
    }
}

void print_usage(const char* program) {
    std::cerr << "Usage: " << program << " [OPTIONS] <config-file>\n"
              << "\n"
              << "A WireGuard-compatible VPN server.\n"
              << "\n"
              << "Options:\n"
              << "  -h, --help        Show this help message\n"
              << "  -v, --verbose     Enable verbose logging\n"
              << "  -d, --debug       Enable debug logging\n"
              << "  --generate-config Generate a sample configuration file\n"
              << "\n"
              << "Example:\n"
              << "  " << program << " /etc/wireguard/wg0.conf\n"
              << "\n"
              << "Configuration file format:\n"
              << "  [Interface]\n"
              << "  PrivateKey = <base64-encoded-private-key>\n"
              << "  ListenPort = 51820\n"
              << "  Address = 10.0.0.1/24\n"
              << "\n"
              << "  [Peer]\n"
              << "  PublicKey = <base64-encoded-public-key>\n"
              << "  AllowedIPs = 10.0.0.2/32\n"
              << "  # Optional: Endpoint = 192.168.1.100:51820\n"
              << "  # Optional: PersistentKeepalive = 25\n";
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    // Parse command line arguments
    std::string config_path;
    vpn::util::LogLevel log_level = vpn::util::LogLevel::Info;
    bool generate_config = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "-v" || arg == "--verbose") {
            log_level = vpn::util::LogLevel::Debug;
        } else if (arg == "-d" || arg == "--debug") {
            log_level = vpn::util::LogLevel::Trace;
        } else if (arg == "--generate-config") {
            generate_config = true;
        } else if (arg[0] != '-') {
            config_path = arg;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // Set log level
    vpn::util::Logger::instance().set_level(log_level);

    // Generate sample config if requested
    if (generate_config) {
        std::cout << vpn::core::ServerConfig::generate_sample();
        return 0;
    }

    // Check for config file
    if (config_path.empty()) {
        std::cerr << "Error: Configuration file required\n\n";
        print_usage(argv[0]);
        return 1;
    }

    // Parse configuration
    auto config = vpn::core::ServerConfig::parse_file(config_path);
    if (!config) {
        LOG_FATAL("Failed to parse configuration file: {}", config_path);
        return 1;
    }

    if (!config->validate()) {
        LOG_FATAL("Invalid configuration");
        return 1;
    }

    // Convert to runtime config
    auto runtime_config = vpn::core::RuntimeConfig::from_config(*config);
    if (!runtime_config) {
        LOG_FATAL("Failed to resolve configuration");
        return 1;
    }

    LOG_INFO("Configuration loaded successfully");
    LOG_INFO("  Listen port: {}", runtime_config->listen_port);
    LOG_INFO("  Peers: {}", runtime_config->peers.size());

    // Set up signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Create and run server
    try {
        vpn::core::Server server(*runtime_config);
        g_server = &server;

        server.run();

        g_server = nullptr;
    } catch (const std::exception& e) {
        LOG_FATAL("Server error: {}", e.what());
        return 1;
    }

    LOG_INFO("Server shutdown complete");
    return 0;
}
