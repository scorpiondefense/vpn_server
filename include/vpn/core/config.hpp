#pragma once

#include "vpn/crypto/curve25519.hpp"
#include "vpn/net/address.hpp"
#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace vpn::core {

// Configuration for a single peer
struct PeerConfig {
    std::string public_key_base64;
    std::optional<std::string> preshared_key_base64;
    std::optional<net::SocketAddress> endpoint;
    std::vector<std::string> allowed_ips;
    std::chrono::seconds persistent_keepalive{0};
};

// Main server configuration
struct ServerConfig {
    // Interface settings
    std::string private_key_base64;
    uint16_t listen_port = 51820;
    std::optional<std::string> interface_name;

    // Addresses to assign to the interface
    std::vector<std::string> addresses;

    // Peer configurations
    std::vector<PeerConfig> peers;

    // Performance settings
    size_t num_threads = 0;  // 0 = auto-detect
    size_t recv_buffer_size = 4 * 1024 * 1024;  // 4 MB
    size_t send_buffer_size = 4 * 1024 * 1024;  // 4 MB

    // MTU
    int mtu = 1420;

    // Parse from WireGuard-style config file
    static std::optional<ServerConfig> parse_file(const std::string& path);

    // Parse from string
    static std::optional<ServerConfig> parse(const std::string& content);

    // Validate configuration
    bool validate() const;

    // Generate sample config
    static std::string generate_sample();
};

// Runtime configuration (resolved from ServerConfig)
struct RuntimeConfig {
    crypto::Curve25519KeyPair keypair;
    uint16_t listen_port;
    std::string interface_name;
    std::vector<std::pair<net::IpAddress, uint8_t>> addresses;
    int mtu;
    size_t num_threads;
    size_t recv_buffer_size;
    size_t send_buffer_size;

    struct ResolvedPeer {
        crypto::PublicKey public_key;
        crypto::PresharedKey preshared_key;
        std::optional<net::SocketAddress> endpoint;
        std::vector<net::Subnet> allowed_ips;
        std::chrono::seconds persistent_keepalive;
    };
    std::vector<ResolvedPeer> peers;

    // Convert from ServerConfig
    static std::optional<RuntimeConfig> from_config(const ServerConfig& config);
};

} // namespace vpn::core
