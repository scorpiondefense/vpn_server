#pragma once

#include "session.hpp"
#include "timer.hpp"
#include "vpn/crypto/curve25519.hpp"
#include "vpn/crypto/noise.hpp"
#include "vpn/net/address.hpp"
#include <memory>
#include <mutex>
#include <vector>
#include <optional>

namespace vpn::protocol {

// Configuration for a peer
struct PeerConfig {
    crypto::PublicKey public_key;
    crypto::PresharedKey preshared_key;
    std::optional<net::SocketAddress> endpoint;
    std::vector<net::Subnet> allowed_ips;
    std::chrono::seconds persistent_keepalive{0};
};

// Represents a WireGuard peer
class Peer {
public:
    explicit Peer(const PeerConfig& config);

    // Get peer's public key
    const crypto::PublicKey& public_key() const { return public_key_; }

    // Get pre-shared key
    const crypto::PresharedKey& preshared_key() const { return preshared_key_; }

    // Get/set endpoint
    std::optional<net::SocketAddress> endpoint() const;
    void set_endpoint(const net::SocketAddress& endpoint);

    // Get allowed IPs
    const std::vector<net::Subnet>& allowed_ips() const { return allowed_ips_; }

    // Check if an IP is allowed for this peer
    bool is_allowed_ip(const net::IpAddress& addr) const;

    // Session management
    std::shared_ptr<Session> current_session() const;
    std::shared_ptr<Session> previous_session() const;

    void set_current_session(std::shared_ptr<Session> session);
    void rotate_session(std::shared_ptr<Session> new_session);

    // Get session by index (for transport data routing)
    std::shared_ptr<Session> session_by_index(uint32_t index) const;

    // Handshake state
    crypto::NoiseHandshake& handshake() { return *handshake_; }
    const crypto::NoiseHandshake& handshake() const { return *handshake_; }
    bool has_handshake() const { return handshake_.has_value(); }

    void reset_handshake(const crypto::Curve25519KeyPair& local_static);

    // Timer access
    PeerTimers& timers() { return timers_; }
    const PeerTimers& timers() const { return timers_; }

    // Replay protection for handshake
    bool check_replay_timestamp(const crypto::Tai64nTimestamp& timestamp);

    // Cookie for DoS protection
    void set_cookie(const std::array<uint8_t, 16>& cookie);
    std::optional<std::array<uint8_t, 16>> cookie() const;
    bool cookie_valid() const;

    // Statistics
    struct Stats {
        uint64_t rx_bytes = 0;
        uint64_t tx_bytes = 0;
        uint64_t rx_packets = 0;
        uint64_t tx_packets = 0;
        std::chrono::steady_clock::time_point last_handshake;
    };

    void add_rx_bytes(size_t bytes);
    void add_tx_bytes(size_t bytes);
    Stats stats() const;

private:
    crypto::PublicKey public_key_;
    crypto::PresharedKey preshared_key_;

    mutable std::mutex endpoint_mutex_;
    std::optional<net::SocketAddress> endpoint_;

    std::vector<net::Subnet> allowed_ips_;

    mutable std::mutex session_mutex_;
    std::shared_ptr<Session> current_session_;
    std::shared_ptr<Session> previous_session_;

    std::optional<crypto::NoiseHandshake> handshake_;
    PeerTimers timers_;

    // Replay protection
    mutable std::mutex replay_mutex_;
    std::optional<crypto::Tai64nTimestamp> last_timestamp_;

    // Cookie for DoS protection
    mutable std::mutex cookie_mutex_;
    std::optional<std::array<uint8_t, 16>> cookie_;
    std::chrono::steady_clock::time_point cookie_time_;

    // Statistics
    mutable std::mutex stats_mutex_;
    Stats stats_;
};

} // namespace vpn::protocol
