#pragma once

#include "mesh_message.hpp"
#include "vpn/net/address.hpp"
#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <vector>

namespace vpn::mesh {

// NAT type classification
enum class NatType {
    Unknown,
    OpenInternet,       // No NAT, public IP
    FullCone,           // Any external host can send to mapped port
    RestrictedCone,     // Only hosts we've sent to can respond (IP restricted)
    PortRestricted,     // Only hosts we've sent to can respond (IP+port restricted)
    Symmetric           // Different mapping for each destination
};

// Result of NAT discovery
struct NatDiscoveryResult {
    NatType type = NatType::Unknown;
    std::optional<net::SocketAddress> reflexive_address;  // Our public IP:port as seen by beacon
    std::optional<net::SocketAddress> local_address;      // Our local IP:port
    bool hairpin_supported = false;
};

// NAT discovery via beacon (STUN-like reflexive address detection)
class NatDiscovery {
public:
    NatDiscovery() = default;

    // Set our reflexive address as reported by beacon
    void set_reflexive_address(const net::SocketAddress& addr);

    // Set our local address
    void set_local_address(const net::SocketAddress& addr);

    // Get current NAT discovery result
    NatDiscoveryResult result() const;

    // Classify NAT type based on collected evidence
    NatType classify() const;

    // Build endpoint list for NodeInfo (local + reflexive)
    std::vector<net::SocketAddress> build_endpoint_list() const;

private:
    mutable std::mutex mutex_;
    NatDiscoveryResult result_;
};

// Hole punching coordinator
class HolePuncher {
public:
    struct PunchAttempt {
        NodeId target_node_id;
        crypto::PublicKey target_public_key;
        std::vector<net::SocketAddress> target_endpoints;
        uint64_t punch_nonce;
        std::chrono::steady_clock::time_point started_at;
        int attempts_remaining;
        bool succeeded = false;
    };

    // Callback for sending UDP packets
    using SendCallback = std::function<bool(const std::vector<uint8_t>& data,
                                            const net::SocketAddress& to)>;

    explicit HolePuncher(SendCallback send_cb);

    // Initiate hole punching to a peer
    void initiate(const NodeInfo& target_info, uint64_t punch_nonce);

    // Process incoming punch notification from beacon
    void handle_punch_notify(const MeshPunchNotify& notify);

    // Periodic tick - sends hole-punch probes
    void tick();

    // Check if we have a successful punch for a target
    bool has_succeeded(const NodeId& target) const;

    // Get active attempts count
    size_t active_attempts() const;

    // Max attempts per peer
    static constexpr int MAX_PUNCH_ATTEMPTS = 10;
    // Interval between punch packets
    static constexpr auto PUNCH_INTERVAL = std::chrono::milliseconds(200);

private:
    SendCallback send_cb_;
    mutable std::mutex mutex_;
    std::vector<PunchAttempt> attempts_;
};

// Relay manager for symmetric NAT fallback
class RelayManager {
public:
    struct RelayRoute {
        NodeId target_node_id;
        crypto::PublicKey relay_peer_key;  // The beacon or intermediate node
        std::chrono::steady_clock::time_point established_at;
    };

    // Register a relay route through a specific peer
    void add_relay(const NodeId& target, const crypto::PublicKey& relay_key);

    // Remove a relay route
    void remove_relay(const NodeId& target);

    // Find relay for a target
    std::optional<crypto::PublicKey> find_relay(const NodeId& target) const;

    // Check if we're relaying for a target
    bool has_relay(const NodeId& target) const;

    // Get all relay routes
    std::vector<RelayRoute> all_routes() const;

private:
    mutable std::mutex mutex_;
    std::vector<RelayRoute> routes_;
};

} // namespace vpn::mesh
