#pragma once

#include "mesh_message.hpp"
#include "mesh_node.hpp"
#include "beacon.hpp"
#include "vpn/core/config.hpp"
#include <string>
#include <optional>
#include <vector>

namespace vpn::mesh {

// Parsed [Mesh] section from config file
struct MeshConfigSection {
    std::string network_name;
    std::string network_secret_base64;
    std::string beacon_address;
    std::string beacon_public_key_base64;
    bool auto_connect = true;
    size_t max_peers = 100;
    std::string ipv6_address;  // e.g., "fd00:mesh::1/64"
};

// Complete mesh node config file (Interface + Mesh sections)
struct MeshConfigFile {
    // Interface section (reuses existing ServerConfig fields)
    std::string private_key_base64;
    uint16_t listen_port = 51820;
    std::string address;  // e.g., "10.100.0.1/16"
    int mtu = 1420;

    // Mesh section
    MeshConfigSection mesh;

    // Parse from file
    static std::optional<MeshConfigFile> parse_file(const std::string& path);

    // Parse from string
    static std::optional<MeshConfigFile> parse(const std::string& content);

    // Validate
    bool validate() const;

    // Resolve to runtime config
    struct ResolvedMeshConfig {
        core::RuntimeConfig server_config;
        MeshNodeConfig mesh_config;
    };
    std::optional<ResolvedMeshConfig> resolve() const;

    // Generate sample config
    static std::string generate_sample();
};

// Beacon config file
struct BeaconConfigFile {
    std::string private_key_base64;
    uint16_t listen_port = 51821;
    std::string network_name;
    std::string network_secret_base64;
    size_t max_peers = 1000;
    int peer_expiry_seconds = 300;

    // Parse from file
    static std::optional<BeaconConfigFile> parse_file(const std::string& path);

    // Parse from string
    static std::optional<BeaconConfigFile> parse(const std::string& content);

    // Validate
    bool validate() const;

    // Resolve to runtime config
    std::optional<BeaconConfig> resolve() const;

    // Generate sample config
    static std::string generate_sample();
};

// Detect if a config file has a [Mesh] section
bool has_mesh_section(const std::string& content);

// Detect if a config file has a [Beacon] section
bool has_beacon_section(const std::string& content);

} // namespace vpn::mesh
