#pragma once

#include "mesh_message.hpp"
#include "kademlia.hpp"
#include "vpn/crypto/curve25519.hpp"
#include "vpn/net/address.hpp"
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace vpn::core {
class Server;
}

namespace vpn::mesh {

// Configuration for mesh node behavior
struct MeshNodeConfig {
    std::string network_name;
    std::vector<uint8_t> network_secret;
    net::SocketAddress beacon_address;
    crypto::PublicKey beacon_public_key;
    net::IpAddress vpn_ipv4;
    std::optional<net::IpAddress> vpn_ipv6;
    bool auto_connect = true;
    size_t max_peers = 100;
    std::chrono::seconds ping_interval{30};
    int max_missed_pings = 3;
};

// Tracked mesh peer with health info
struct MeshPeer {
    NodeInfo info;
    bool connected = false;
    uint64_t last_ping_nonce = 0;
    std::chrono::steady_clock::time_point last_ping_sent;
    std::chrono::steady_clock::time_point last_pong_received;
    int missed_pings = 0;
    std::chrono::microseconds rtt{0};
};

// Mesh node overlay — manages discovery, peer lifecycle, and DHT
class MeshNode {
public:
    MeshNode(const MeshNodeConfig& config, const crypto::Curve25519KeyPair& keypair,
             core::Server& server);
    ~MeshNode() = default;

    MeshNode(const MeshNode&) = delete;
    MeshNode& operator=(const MeshNode&) = delete;

    // Called by Server when a mesh message is received
    void handle_mesh_message(std::span<const uint8_t> data,
                             const crypto::PublicKey& from_peer_key);

    // Called by Server's timer loop
    void mesh_timer_tick();

    // Start mesh operations (register with beacon)
    void start();

    // Get local node ID
    const NodeId& node_id() const { return local_node_id_; }

    // Get connected mesh peers
    std::vector<MeshPeer> connected_peers() const;

    // Get mesh stats
    struct MeshStats {
        size_t total_peers = 0;
        size_t connected_peers = 0;
        size_t routing_table_size = 0;
        size_t dht_entries = 0;
    };
    MeshStats stats() const;

    // Build the registration message to send to beacon
    std::vector<uint8_t> build_register_message() const;

private:
    // Message handlers
    void handle_register_ack(const MeshRegisterAck& msg);
    void handle_peer_list(const MeshPeerList& msg);
    void handle_mesh_ping(const MeshPing& msg, const crypto::PublicKey& from);
    void handle_mesh_pong(const MeshPong& msg, const crypto::PublicKey& from);
    void handle_find_node(const MeshFindNode& msg, const crypto::PublicKey& from);
    void handle_find_node_response(const MeshFindNodeResponse& msg);
    void handle_find_value_response(const MeshFindValueResponse& msg);
    void handle_punch_notify(const MeshPunchNotify& msg);
    void handle_route_advertise(const MeshRouteAdvertise& msg, const crypto::PublicKey& from);

    // Periodic actions
    void ping_peers();
    void check_peer_health();
    void refresh_dht_buckets();
    void request_peer_list_update();

    // Connect to a discovered peer
    void connect_to_peer(const NodeInfo& info);

    // Send mesh message to a specific peer (via WireGuard transport)
    bool send_to_peer(const crypto::PublicKey& peer_key, const std::vector<uint8_t>& mesh_data);

    // Send mesh message to beacon
    bool send_to_beacon(const std::vector<uint8_t>& mesh_data);

    // Configuration
    MeshNodeConfig config_;
    crypto::Curve25519KeyPair keypair_;
    NodeId local_node_id_;

    // Reference to the server for sending packets and adding peers
    core::Server& server_;

    // State
    bool registered_ = false;
    std::chrono::steady_clock::time_point last_register_attempt_;
    std::chrono::steady_clock::time_point last_peer_list_request_;

    // Kademlia
    RoutingTable routing_table_;
    DhtStore dht_store_;

    // Mesh peers
    mutable std::mutex peers_mutex_;
    std::unordered_map<std::string, MeshPeer> mesh_peers_;  // keyed by pubkey base64

    // Ping state
    uint64_t next_ping_nonce_ = 1;

    // Timer intervals
    std::chrono::steady_clock::time_point last_ping_time_;
    std::chrono::steady_clock::time_point last_health_check_;
    std::chrono::steady_clock::time_point last_dht_refresh_;

    // Helper to get peer key as string
    static std::string peer_key_str(const crypto::PublicKey& key);
};

} // namespace vpn::mesh
