#include "vpn/core/server.hpp"
#include "vpn/core/config.hpp"
#include "vpn/mesh/mesh_node.hpp"
#include "vpn/mesh/mesh_config.hpp"
#include "vpn/util/logger.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
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
              << "A WireGuard-compatible VPN server with mesh networking.\n"
              << "\n"
              << "Options:\n"
              << "  -h, --help              Show this help message\n"
              << "  -v, --verbose           Enable verbose logging\n"
              << "  -d, --debug             Enable debug logging\n"
              << "  --generate-config       Generate a sample server configuration\n"
              << "  --generate-mesh-config  Generate a sample mesh node configuration\n"
              << "\n"
              << "Mesh mode (CLI flags, no config file needed):\n"
              << "  --network <name>        Network name\n"
              << "  --network-secret <b64>  Base64-encoded network secret\n"
              << "  --address <ip/prefix>   VPN address (e.g., 10.100.0.1/16)\n"
              << "  --beacon <addr:port>    Beacon server address\n"
              << "  --beacon-key <b64>      Beacon public key (base64)\n"
              << "\n"
              << "Modes:\n"
              << "  Standard WireGuard:  " << program << " server.conf\n"
              << "  Mesh VPN node:       " << program << " mesh-node.conf   (config with [Mesh] section)\n"
              << "  Mesh VPN node (CLI): " << program << " --network mynet --address 10.100.0.1/16 \\\n"
              << "                              --beacon beacon.example.com:51821 --beacon-key <b64> \\\n"
              << "                              --network-secret <b64>\n";
}

int run_standard_mode(const std::string& config_path) {
    auto config = vpn::core::ServerConfig::parse_file(config_path);
    if (!config) {
        LOG_FATAL("Failed to parse configuration file: {}", config_path);
        return 1;
    }

    if (!config->validate()) {
        LOG_FATAL("Invalid configuration");
        return 1;
    }

    auto runtime_config = vpn::core::RuntimeConfig::from_config(*config);
    if (!runtime_config) {
        LOG_FATAL("Failed to resolve configuration");
        return 1;
    }

    LOG_INFO("Configuration loaded successfully");
    LOG_INFO("  Listen port: {}", runtime_config->listen_port);
    LOG_INFO("  Peers: {}", runtime_config->peers.size());

    vpn::core::Server server(*runtime_config);
    g_server = &server;

    server.run();

    g_server = nullptr;
    return 0;
}

int run_mesh_mode(const vpn::mesh::MeshConfigFile::ResolvedMeshConfig& resolved) {
    LOG_INFO("Starting in mesh mode");
    LOG_INFO("  Network: {}", resolved.mesh_config.network_name);
    LOG_INFO("  VPN address: {}", resolved.mesh_config.vpn_ipv4.to_string());
    LOG_INFO("  Beacon: {}", resolved.mesh_config.beacon_address.to_string());

    vpn::core::Server server(resolved.server_config);
    g_server = &server;

    // Create mesh node overlay
    vpn::mesh::MeshNode mesh_node(resolved.mesh_config,
                                   resolved.server_config.keypair,
                                   server);
    server.set_mesh_node(&mesh_node);

    // Start mesh operations
    mesh_node.start();

    // Run the server (blocks)
    server.run();

    g_server = nullptr;
    return 0;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    std::string config_path;
    vpn::util::LogLevel log_level = vpn::util::LogLevel::Info;
    bool generate_config = false;
    bool generate_mesh_config = false;

    // CLI mesh overrides
    std::string cli_network;
    std::string cli_network_secret;
    std::string cli_address;
    std::string cli_beacon;
    std::string cli_beacon_key;

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
        } else if (arg == "--generate-mesh-config") {
            generate_mesh_config = true;
        } else if (arg == "--network" && i + 1 < argc) {
            cli_network = argv[++i];
        } else if (arg == "--network-secret" && i + 1 < argc) {
            cli_network_secret = argv[++i];
        } else if (arg == "--address" && i + 1 < argc) {
            cli_address = argv[++i];
        } else if (arg == "--beacon" && i + 1 < argc) {
            cli_beacon = argv[++i];
        } else if (arg == "--beacon-key" && i + 1 < argc) {
            cli_beacon_key = argv[++i];
        } else if (arg[0] != '-') {
            config_path = arg;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    vpn::util::Logger::instance().set_level(log_level);

    // Generate sample configs
    if (generate_config) {
        std::cout << vpn::core::ServerConfig::generate_sample();
        return 0;
    }
    if (generate_mesh_config) {
        std::cout << vpn::mesh::MeshConfigFile::generate_sample();
        return 0;
    }

    // Set up signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Check for CLI-based mesh mode
    if (!cli_network.empty()) {
        if (cli_network_secret.empty() || cli_address.empty() ||
            cli_beacon.empty() || cli_beacon_key.empty()) {
            std::cerr << "Error: --network, --network-secret, --address, --beacon, and --beacon-key are all required for CLI mesh mode\n\n";
            print_usage(argv[0]);
            return 1;
        }

        // Build a config from CLI args
        std::ostringstream config_str;
        auto keypair = vpn::crypto::Curve25519KeyPair::generate();
        config_str << "[Interface]\n";
        config_str << "PrivateKey = " << keypair.private_key_base64() << "\n";
        config_str << "ListenPort = 51820\n";
        config_str << "Address = " << cli_address << "\n";
        config_str << "\n";
        config_str << "[Mesh]\n";
        config_str << "NetworkName = " << cli_network << "\n";
        config_str << "NetworkSecret = " << cli_network_secret << "\n";
        config_str << "BeaconAddress = " << cli_beacon << "\n";
        config_str << "BeaconPublicKey = " << cli_beacon_key << "\n";
        config_str << "AutoConnect = true\n";

        auto mesh_config = vpn::mesh::MeshConfigFile::parse(config_str.str());
        if (!mesh_config) {
            LOG_FATAL("Failed to parse CLI mesh configuration");
            return 1;
        }

        auto resolved = mesh_config->resolve();
        if (!resolved) {
            LOG_FATAL("Failed to resolve mesh configuration");
            return 1;
        }

        LOG_INFO("Public key: {}", keypair.public_key_base64());

        try {
            return run_mesh_mode(*resolved);
        } catch (const std::exception& e) {
            LOG_FATAL("Server error: {}", e.what());
            return 1;
        }
    }

    // Config file mode
    if (config_path.empty()) {
        std::cerr << "Error: Configuration file or --network flag required\n\n";
        print_usage(argv[0]);
        return 1;
    }

    // Read config file to detect mode
    std::ifstream file(config_path);
    if (!file) {
        LOG_FATAL("Cannot open configuration file: {}", config_path);
        return 1;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    auto content = buffer.str();
    file.close();

    try {
        if (vpn::mesh::has_mesh_section(content)) {
            // Mesh mode
            auto mesh_config = vpn::mesh::MeshConfigFile::parse(content);
            if (!mesh_config || !mesh_config->validate()) {
                LOG_FATAL("Invalid mesh configuration in: {}", config_path);
                return 1;
            }

            auto resolved = mesh_config->resolve();
            if (!resolved) {
                LOG_FATAL("Failed to resolve mesh configuration");
                return 1;
            }

            return run_mesh_mode(*resolved);
        } else {
            // Standard WireGuard mode
            return run_standard_mode(config_path);
        }
    } catch (const std::exception& e) {
        LOG_FATAL("Server error: {}", e.what());
        return 1;
    }

    LOG_INFO("Server shutdown complete");
    return 0;
}
