#include "vpn/mesh/mesh_config.hpp"
#include "vpn/core/config.hpp"
#include "vpn/util/base64.hpp"
#include "vpn/util/logger.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace vpn::mesh {

namespace {

std::string trim(const std::string& str) {
    auto start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

std::string to_lower(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return str;
}

std::pair<std::string, std::string> parse_line(const std::string& line) {
    auto eq = line.find('=');
    if (eq == std::string::npos) {
        return {trim(line), ""};
    }
    return {trim(line.substr(0, eq)), trim(line.substr(eq + 1))};
}

} // anonymous namespace

// --- MeshConfigFile ---

std::optional<MeshConfigFile> MeshConfigFile::parse_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) return std::nullopt;

    std::stringstream buffer;
    buffer << file.rdbuf();
    return parse(buffer.str());
}

std::optional<MeshConfigFile> MeshConfigFile::parse(const std::string& content) {
    MeshConfigFile config;
    std::istringstream stream(content);
    std::string line;

    enum class Section { None, Interface, Mesh };
    Section current_section = Section::None;

    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        if (line[0] == '[') {
            auto header = to_lower(trim(line.substr(1, line.find(']') - 1)));
            if (header == "interface") {
                current_section = Section::Interface;
            } else if (header == "mesh") {
                current_section = Section::Mesh;
            }
            continue;
        }

        auto [key, value] = parse_line(line);
        key = to_lower(key);

        if (current_section == Section::Interface) {
            if (key == "privatekey") {
                config.private_key_base64 = value;
            } else if (key == "listenport") {
                config.listen_port = static_cast<uint16_t>(std::stoi(value));
            } else if (key == "address") {
                config.address = value;
            } else if (key == "mtu") {
                config.mtu = std::stoi(value);
            }
        } else if (current_section == Section::Mesh) {
            if (key == "networkname") {
                config.mesh.network_name = value;
            } else if (key == "networksecret") {
                config.mesh.network_secret_base64 = value;
            } else if (key == "beaconaddress") {
                config.mesh.beacon_address = value;
            } else if (key == "beaconpublickey") {
                config.mesh.beacon_public_key_base64 = value;
            } else if (key == "autoconnect") {
                config.mesh.auto_connect = (to_lower(value) == "true" || value == "1");
            } else if (key == "maxpeers") {
                config.mesh.max_peers = static_cast<size_t>(std::stoi(value));
            } else if (key == "ipv6address") {
                config.mesh.ipv6_address = value;
            }
        }
    }

    return config;
}

bool MeshConfigFile::validate() const {
    if (private_key_base64.empty()) return false;
    if (address.empty()) return false;
    if (mesh.network_name.empty()) return false;
    if (mesh.network_secret_base64.empty()) return false;
    if (mesh.beacon_address.empty()) return false;
    if (mesh.beacon_public_key_base64.empty()) return false;

    auto key = util::base64_decode(private_key_base64);
    if (!key || key->size() != 32) return false;

    auto secret = util::base64_decode(mesh.network_secret_base64);
    if (!secret) return false;

    auto beacon_key = util::base64_decode(mesh.beacon_public_key_base64);
    if (!beacon_key || beacon_key->size() != 32) return false;

    return true;
}

std::optional<MeshConfigFile::ResolvedMeshConfig> MeshConfigFile::resolve() const {
    if (!validate()) return std::nullopt;

    ResolvedMeshConfig resolved;

    // Build ServerConfig for the runtime
    auto keypair = crypto::Curve25519KeyPair::from_base64(private_key_base64);
    if (!keypair) return std::nullopt;

    resolved.server_config.keypair = *keypair;
    resolved.server_config.listen_port = listen_port;
    resolved.server_config.interface_name = "wg0";
    resolved.server_config.mtu = mtu;
    resolved.server_config.num_threads = 0;
    resolved.server_config.recv_buffer_size = 4 * 1024 * 1024;
    resolved.server_config.send_buffer_size = 4 * 1024 * 1024;

    // Parse address
    auto subnet = net::Subnet::parse(address);
    if (subnet) {
        resolved.server_config.addresses.emplace_back(subnet->address(), subnet->prefix_length());
    }

    // Build MeshNodeConfig
    resolved.mesh_config.network_name = mesh.network_name;

    auto secret = util::base64_decode(mesh.network_secret_base64);
    if (!secret) return std::nullopt;
    resolved.mesh_config.network_secret = *secret;

    auto beacon_addr = net::SocketAddress::parse(mesh.beacon_address);
    if (!beacon_addr) return std::nullopt;
    resolved.mesh_config.beacon_address = *beacon_addr;

    auto beacon_key = util::base64_decode(mesh.beacon_public_key_base64);
    if (!beacon_key || beacon_key->size() != 32) return std::nullopt;
    std::memcpy(resolved.mesh_config.beacon_public_key.data(), beacon_key->data(), 32);

    // VPN address
    if (subnet) {
        resolved.mesh_config.vpn_ipv4 = subnet->address();
    }

    // IPv6 address
    if (!mesh.ipv6_address.empty()) {
        auto ipv6_subnet = net::Subnet::parse(mesh.ipv6_address);
        if (ipv6_subnet) {
            resolved.mesh_config.vpn_ipv6 = ipv6_subnet->address();
            resolved.server_config.addresses.emplace_back(
                ipv6_subnet->address(), ipv6_subnet->prefix_length());
        }
    }

    resolved.mesh_config.auto_connect = mesh.auto_connect;
    resolved.mesh_config.max_peers = mesh.max_peers;

    return resolved;
}

std::string MeshConfigFile::generate_sample() {
    auto keypair = crypto::Curve25519KeyPair::generate();

    std::ostringstream oss;
    oss << "[Interface]\n";
    oss << "PrivateKey = " << keypair.private_key_base64() << "\n";
    oss << "ListenPort = 51820\n";
    oss << "Address = 10.100.0.1/16\n";
    oss << "\n";
    oss << "[Mesh]\n";
    oss << "NetworkName = my-network\n";
    oss << "NetworkSecret = <base64-encoded-shared-secret>\n";
    oss << "BeaconAddress = beacon.example.com:51821\n";
    oss << "BeaconPublicKey = <beacon-public-key>\n";
    oss << "AutoConnect = true\n";
    oss << "MaxPeers = 100\n";
    oss << "# IPv6Address = fd00:mesh::1/64\n";

    return oss.str();
}

// --- BeaconConfigFile ---

std::optional<BeaconConfigFile> BeaconConfigFile::parse_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) return std::nullopt;

    std::stringstream buffer;
    buffer << file.rdbuf();
    return parse(buffer.str());
}

std::optional<BeaconConfigFile> BeaconConfigFile::parse(const std::string& content) {
    BeaconConfigFile config;
    std::istringstream stream(content);
    std::string line;

    enum class Section { None, Interface, Beacon };
    Section current_section = Section::None;

    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        if (line[0] == '[') {
            auto header = to_lower(trim(line.substr(1, line.find(']') - 1)));
            if (header == "interface") {
                current_section = Section::Interface;
            } else if (header == "beacon") {
                current_section = Section::Beacon;
            }
            continue;
        }

        auto [key, value] = parse_line(line);
        key = to_lower(key);

        if (current_section == Section::Interface) {
            if (key == "privatekey") {
                config.private_key_base64 = value;
            } else if (key == "listenport") {
                config.listen_port = static_cast<uint16_t>(std::stoi(value));
            }
        } else if (current_section == Section::Beacon) {
            if (key == "networkname") {
                config.network_name = value;
            } else if (key == "networksecret") {
                config.network_secret_base64 = value;
            } else if (key == "maxpeers") {
                config.max_peers = static_cast<size_t>(std::stoi(value));
            } else if (key == "peerexpiry") {
                config.peer_expiry_seconds = std::stoi(value);
            }
        }
    }

    return config;
}

bool BeaconConfigFile::validate() const {
    if (private_key_base64.empty()) return false;
    if (network_name.empty()) return false;
    if (network_secret_base64.empty()) return false;

    auto key = util::base64_decode(private_key_base64);
    if (!key || key->size() != 32) return false;

    auto secret = util::base64_decode(network_secret_base64);
    if (!secret) return false;

    return true;
}

std::optional<BeaconConfig> BeaconConfigFile::resolve() const {
    if (!validate()) return std::nullopt;

    BeaconConfig config;

    auto keypair = crypto::Curve25519KeyPair::from_base64(private_key_base64);
    if (!keypair) return std::nullopt;
    config.keypair = *keypair;

    config.listen_port = listen_port;
    config.network_name = network_name;

    auto secret = util::base64_decode(network_secret_base64);
    if (!secret) return std::nullopt;
    config.network_secret = *secret;

    config.max_peers = max_peers;
    config.peer_expiry = std::chrono::seconds(peer_expiry_seconds);

    return config;
}

std::string BeaconConfigFile::generate_sample() {
    auto keypair = crypto::Curve25519KeyPair::generate();

    std::ostringstream oss;
    oss << "[Interface]\n";
    oss << "PrivateKey = " << keypair.private_key_base64() << "\n";
    oss << "ListenPort = 51821\n";
    oss << "\n";
    oss << "[Beacon]\n";
    oss << "NetworkName = my-network\n";
    oss << "NetworkSecret = <base64-encoded-shared-secret>\n";
    oss << "MaxPeers = 1000\n";
    oss << "PeerExpiry = 300\n";

    return oss.str();
}

// --- Utility ---

bool has_mesh_section(const std::string& content) {
    auto lower = content;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return lower.find("[mesh]") != std::string::npos;
}

bool has_beacon_section(const std::string& content) {
    auto lower = content;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return lower.find("[beacon]") != std::string::npos;
}

} // namespace vpn::mesh
