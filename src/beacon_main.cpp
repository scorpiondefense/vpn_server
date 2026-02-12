#include "vpn/mesh/beacon.hpp"
#include "vpn/mesh/mesh_config.hpp"
#include "vpn/util/logger.hpp"
#include "vpn/util/base64.hpp"
#include <iostream>
#include <csignal>

namespace {

vpn::mesh::Beacon* g_beacon = nullptr;

void signal_handler(int signum) {
    if (g_beacon) {
        std::cout << "\nReceived signal " << signum << ", shutting down beacon...\n";
        g_beacon->stop();
    }
}

void print_usage(const char* program) {
    std::cerr << "Usage: " << program << " [OPTIONS] [config-file]\n"
              << "\n"
              << "A mesh VPN beacon (centralized discovery) server.\n"
              << "\n"
              << "Options:\n"
              << "  -h, --help              Show this help message\n"
              << "  -v, --verbose           Enable verbose logging\n"
              << "  -d, --debug             Enable debug logging\n"
              << "  --listen <addr:port>    Listen address (default: 0.0.0.0:51821)\n"
              << "  --network <name>        Network name\n"
              << "  --network-secret <b64>  Base64-encoded network secret\n"
              << "  --max-peers <n>         Maximum peers (default: 1000)\n"
              << "  --peer-expiry <secs>    Peer expiry time (default: 300)\n"
              << "  --generate-config       Generate a sample beacon configuration\n"
              << "\n"
              << "Example:\n"
              << "  " << program << " /etc/wireguard/beacon.conf\n"
              << "  " << program << " --listen 0.0.0.0:51821 --network mynet --network-secret <b64>\n";
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    std::string config_path;
    vpn::util::LogLevel log_level = vpn::util::LogLevel::Info;
    bool generate_config = false;

    // CLI overrides
    std::string cli_listen;
    std::string cli_network;
    std::string cli_network_secret;
    int cli_max_peers = -1;
    int cli_peer_expiry = -1;

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
        } else if (arg == "--listen" && i + 1 < argc) {
            cli_listen = argv[++i];
        } else if (arg == "--network" && i + 1 < argc) {
            cli_network = argv[++i];
        } else if (arg == "--network-secret" && i + 1 < argc) {
            cli_network_secret = argv[++i];
        } else if (arg == "--max-peers" && i + 1 < argc) {
            cli_max_peers = std::stoi(argv[++i]);
        } else if (arg == "--peer-expiry" && i + 1 < argc) {
            cli_peer_expiry = std::stoi(argv[++i]);
        } else if (arg[0] != '-') {
            config_path = arg;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    vpn::util::Logger::instance().set_level(log_level);

    if (generate_config) {
        std::cout << vpn::mesh::BeaconConfigFile::generate_sample();
        return 0;
    }

    vpn::mesh::BeaconConfig beacon_config;

    if (!config_path.empty()) {
        // Parse from config file
        auto file_config = vpn::mesh::BeaconConfigFile::parse_file(config_path);
        if (!file_config) {
            LOG_FATAL("Failed to parse beacon configuration file: {}", config_path);
            return 1;
        }

        auto resolved = file_config->resolve();
        if (!resolved) {
            LOG_FATAL("Failed to resolve beacon configuration");
            return 1;
        }
        beacon_config = *resolved;
    } else {
        // Build from CLI args
        if (cli_network.empty() || cli_network_secret.empty()) {
            std::cerr << "Error: --network and --network-secret are required (or provide a config file)\n\n";
            print_usage(argv[0]);
            return 1;
        }

        beacon_config.keypair = vpn::crypto::Curve25519KeyPair::generate();
        beacon_config.network_name = cli_network;

        auto secret = vpn::util::base64_decode(cli_network_secret);
        if (!secret) {
            LOG_FATAL("Invalid base64 network secret");
            return 1;
        }
        beacon_config.network_secret = *secret;

        if (!cli_listen.empty()) {
            auto addr = vpn::net::SocketAddress::parse(cli_listen);
            if (addr) {
                beacon_config.listen_port = addr->port();
            }
        }
    }

    // Apply CLI overrides
    if (cli_max_peers > 0) {
        beacon_config.max_peers = static_cast<size_t>(cli_max_peers);
    }
    if (cli_peer_expiry > 0) {
        beacon_config.peer_expiry = std::chrono::seconds(cli_peer_expiry);
    }

    LOG_INFO("Beacon configuration loaded");
    LOG_INFO("  Network: {}", beacon_config.network_name);
    LOG_INFO("  Listen port: {}", beacon_config.listen_port);
    LOG_INFO("  Max peers: {}", beacon_config.max_peers);

    // Set up signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    try {
        vpn::mesh::Beacon beacon(beacon_config);
        g_beacon = &beacon;

        LOG_INFO("Beacon public key: {}", beacon_config.keypair.public_key_base64());

        beacon.run();

        g_beacon = nullptr;
    } catch (const std::exception& e) {
        LOG_FATAL("Beacon error: {}", e.what());
        return 1;
    }

    LOG_INFO("Beacon shutdown complete");
    return 0;
}
