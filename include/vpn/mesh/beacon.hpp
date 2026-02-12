#pragma once

#include "mesh_message.hpp"
#include "kademlia.hpp"
#include "vpn/crypto/curve25519.hpp"
#include "vpn/crypto/noise.hpp"
#include "vpn/net/udp_socket.hpp"
#include "vpn/protocol/peer.hpp"
#include "vpn/protocol/message.hpp"
#include "vpn/core/thread_pool.hpp"

#include <atomic>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <chrono>

namespace vpn::mesh {

// Configuration for the beacon server
struct BeaconConfig {
    crypto::Curve25519KeyPair keypair;
    uint16_t listen_port = 51821;
    std::string network_name;
    std::vector<uint8_t> network_secret;
    size_t max_peers = 1000;
    std::chrono::seconds peer_expiry{300};
    size_t num_threads = 0;
};

// Registered mesh node in the beacon
struct RegisteredNode {
    NodeInfo info;
    std::shared_ptr<protocol::Peer> peer;
    std::chrono::steady_clock::time_point registered_at;
    std::chrono::steady_clock::time_point last_seen;
};

// The beacon server — centralized rendezvous for mesh nodes
class Beacon {
public:
    explicit Beacon(const BeaconConfig& config);
    ~Beacon();

    Beacon(const Beacon&) = delete;
    Beacon& operator=(const Beacon&) = delete;

    // Start the beacon (blocks until stop() is called)
    void run();

    // Stop the beacon
    void stop();

    // Check if running
    bool running() const { return running_.load(std::memory_order_relaxed); }

    // Get public key
    const crypto::PublicKey& public_key() const { return config_.keypair.public_key(); }

    // Get number of registered nodes
    size_t node_count() const;

private:
    // Event loops
    void udp_receive_loop();
    void timer_loop();

    // WireGuard packet handling
    void handle_udp_packet(std::span<const uint8_t> data, const net::SocketAddress& from);
    void handle_handshake_initiation(const protocol::HandshakeInitiation& msg,
                                     const net::SocketAddress& from);
    void handle_handshake_response(const protocol::HandshakeResponse& msg,
                                   const net::SocketAddress& from);
    void handle_transport_data(const protocol::TransportData& msg,
                               const net::SocketAddress& from);

    // Mesh message handling (called after WireGuard decryption)
    void handle_mesh_message(std::span<const uint8_t> plaintext,
                             std::shared_ptr<protocol::Peer> peer,
                             const net::SocketAddress& from);

    void handle_register(const MeshRegister& msg, std::shared_ptr<protocol::Peer> peer);
    void handle_peer_list_request(const MeshPeerListRequest& msg,
                                   std::shared_ptr<protocol::Peer> peer);
    void handle_find_node(const MeshFindNode& msg, std::shared_ptr<protocol::Peer> peer);
    void handle_find_value(const MeshFindValue& msg, std::shared_ptr<protocol::Peer> peer);
    void handle_store(const MeshStore& msg, std::shared_ptr<protocol::Peer> peer);
    void handle_punch_request(const MeshPunchRequest& msg, std::shared_ptr<protocol::Peer> peer);

    // Send mesh message to a peer (wraps in WireGuard transport)
    bool send_mesh_message(protocol::Peer& peer, const std::vector<uint8_t>& mesh_data);

    // Send handshake initiation to a peer
    bool send_handshake_initiation(protocol::Peer& peer);

    // Validate network secret
    bool validate_network_secret(const std::vector<uint8_t>& secret) const;

    // Expire stale nodes
    void expire_nodes();

    // Peer lookup
    std::shared_ptr<protocol::Peer> find_peer_by_public_key(const crypto::PublicKey& key);
    std::shared_ptr<protocol::Peer> find_peer_by_session_index(uint32_t index);

    // Session index management
    void register_session_index(uint32_t index, std::shared_ptr<protocol::Peer> peer);

    // Configuration
    BeaconConfig config_;
    NodeId local_node_id_;

    // Network
    net::UdpSocket udp_socket_;

    // Cookie handling
    crypto::CookieGenerator cookie_generator_;

    // Kademlia
    RoutingTable routing_table_;
    DhtStore dht_store_;

    // Registered nodes
    mutable std::shared_mutex nodes_mutex_;
    std::unordered_map<std::string, RegisteredNode> registered_nodes_;  // keyed by pubkey base64

    // WireGuard peers (for encrypted communication)
    mutable std::shared_mutex peers_mutex_;
    std::vector<std::shared_ptr<protocol::Peer>> peers_;
    std::unordered_map<uint32_t, std::weak_ptr<protocol::Peer>> session_index_map_;

    // Thread pool
    std::unique_ptr<core::ThreadPool> thread_pool_;

    // Worker threads
    std::thread udp_thread_;
    std::thread timer_thread_;

    // State
    std::atomic<bool> running_{false};
};

} // namespace vpn::mesh
