#include "vpn/core/config.hpp"
#include "vpn/util/base64.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace vpn::core {

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

std::optional<ServerConfig> ServerConfig::parse_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        return std::nullopt;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return parse(buffer.str());
}

std::optional<ServerConfig> ServerConfig::parse(const std::string& content) {
    ServerConfig config;
    std::istringstream stream(content);
    std::string line;

    enum class Section { None, Interface, Peer };
    Section current_section = Section::None;
    PeerConfig current_peer;

    auto commit_peer = [&]() {
        if (!current_peer.public_key_base64.empty()) {
            config.peers.push_back(std::move(current_peer));
            current_peer = PeerConfig{};
        }
    };

    while (std::getline(stream, line)) {
        line = trim(line);

        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // Check for section headers
        if (line[0] == '[') {
            commit_peer();

            auto header = to_lower(trim(line.substr(1, line.find(']') - 1)));
            if (header == "interface") {
                current_section = Section::Interface;
            } else if (header == "peer") {
                current_section = Section::Peer;
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
                // Can be comma-separated
                std::istringstream addr_stream(value);
                std::string addr;
                while (std::getline(addr_stream, addr, ',')) {
                    config.addresses.push_back(trim(addr));
                }
            } else if (key == "mtu") {
                config.mtu = std::stoi(value);
            }
        } else if (current_section == Section::Peer) {
            if (key == "publickey") {
                current_peer.public_key_base64 = value;
            } else if (key == "presharedkey") {
                current_peer.preshared_key_base64 = value;
            } else if (key == "endpoint") {
                current_peer.endpoint = net::SocketAddress::parse(value);
            } else if (key == "allowedips") {
                std::istringstream ips_stream(value);
                std::string ip;
                while (std::getline(ips_stream, ip, ',')) {
                    current_peer.allowed_ips.push_back(trim(ip));
                }
            } else if (key == "persistentkeepalive") {
                current_peer.persistent_keepalive = std::chrono::seconds(std::stoi(value));
            }
        }
    }

    commit_peer();
    return config;
}

bool ServerConfig::validate() const {
    // Must have private key
    if (private_key_base64.empty()) {
        return false;
    }

    // Validate private key is valid base64 of correct length
    auto decoded = util::base64_decode(private_key_base64);
    if (!decoded || decoded->size() != 32) {
        return false;
    }

    // Port must be valid
    if (listen_port == 0) {
        return false;
    }

    // Each peer must have a public key
    for (const auto& peer : peers) {
        if (peer.public_key_base64.empty()) {
            return false;
        }

        auto peer_key = util::base64_decode(peer.public_key_base64);
        if (!peer_key || peer_key->size() != 32) {
            return false;
        }

        // Validate PSK if present
        if (peer.preshared_key_base64) {
            auto psk = util::base64_decode(*peer.preshared_key_base64);
            if (!psk || psk->size() != 32) {
                return false;
            }
        }
    }

    return true;
}

std::string ServerConfig::generate_sample() {
    auto keypair = crypto::Curve25519KeyPair::generate();

    std::ostringstream oss;
    oss << "[Interface]\n";
    oss << "# Server private key (keep secret!)\n";
    oss << "PrivateKey = " << keypair.private_key_base64() << "\n";
    oss << "# UDP port to listen on\n";
    oss << "ListenPort = 51820\n";
    oss << "# IP addresses for the interface (comma-separated)\n";
    oss << "Address = 10.0.0.1/24, fd00::1/64\n";
    oss << "\n";
    oss << "[Peer]\n";
    oss << "# Client public key\n";
    oss << "PublicKey = <client-public-key>\n";
    oss << "# Optional pre-shared key for additional security\n";
    oss << "# PresharedKey = <psk>\n";
    oss << "# IPs the client is allowed to have\n";
    oss << "AllowedIPs = 10.0.0.2/32\n";
    oss << "# Optional: send keepalive every N seconds\n";
    oss << "# PersistentKeepalive = 25\n";

    return oss.str();
}

std::optional<RuntimeConfig> RuntimeConfig::from_config(const ServerConfig& config) {
    if (!config.validate()) {
        return std::nullopt;
    }

    RuntimeConfig runtime;

    // Parse private key
    auto keypair = crypto::Curve25519KeyPair::from_base64(config.private_key_base64);
    if (!keypair) {
        return std::nullopt;
    }
    runtime.keypair = *keypair;

    runtime.listen_port = config.listen_port;
    runtime.interface_name = config.interface_name.value_or("wg0");
    runtime.mtu = config.mtu;
    runtime.num_threads = config.num_threads;
    runtime.recv_buffer_size = config.recv_buffer_size;
    runtime.send_buffer_size = config.send_buffer_size;

    // Parse addresses
    for (const auto& addr_str : config.addresses) {
        auto subnet = net::Subnet::parse(addr_str);
        if (subnet) {
            runtime.addresses.emplace_back(subnet->address(), subnet->prefix_length());
        }
    }

    // Parse peers
    for (const auto& peer_config : config.peers) {
        ResolvedPeer peer;

        // Public key
        auto pub_key = util::base64_decode(peer_config.public_key_base64);
        if (!pub_key || pub_key->size() != 32) {
            return std::nullopt;
        }
        std::memcpy(peer.public_key.data(), pub_key->data(), 32);

        // PSK
        if (peer_config.preshared_key_base64) {
            auto psk = util::base64_decode(*peer_config.preshared_key_base64);
            if (psk && psk->size() == 32) {
                std::memcpy(peer.preshared_key.data(), psk->data(), 32);
            }
        }

        peer.endpoint = peer_config.endpoint;

        // Allowed IPs
        for (const auto& ip_str : peer_config.allowed_ips) {
            auto subnet = net::Subnet::parse(ip_str);
            if (subnet) {
                peer.allowed_ips.push_back(*subnet);
            }
        }

        peer.persistent_keepalive = peer_config.persistent_keepalive;

        runtime.peers.push_back(std::move(peer));
    }

    return runtime;
}

} // namespace vpn::core
