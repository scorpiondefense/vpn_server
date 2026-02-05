#pragma once

#include "config.hpp"
#include "thread_pool.hpp"
#include "vpn/crypto/noise.hpp"
#include "vpn/net/udp_socket.hpp"
#include "vpn/net/tun_device.hpp"
#include "vpn/protocol/peer.hpp"
#include "vpn/protocol/message.hpp"

#include <atomic>
#include <memory>
#include <unordered_map>
#include <shared_mutex>

namespace vpn::core {

// The main WireGuard server
class Server {
public:
    explicit Server(const RuntimeConfig& config);
    ~Server();

    // Non-copyable and non-movable
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Start the server (blocks until stop() is called)
    void run();

    // Stop the server
    void stop();

    // Check if running
    bool running() const { return running_.load(std::memory_order_relaxed); }

    // Add a peer dynamically
    void add_peer(const RuntimeConfig::ResolvedPeer& peer_config);

    // Remove a peer
    void remove_peer(const crypto::PublicKey& public_key);

    // Get server public key
    const crypto::PublicKey& public_key() const { return keypair_.public_key(); }

    // Get statistics
    struct Stats {
        uint64_t rx_bytes = 0;
        uint64_t tx_bytes = 0;
        uint64_t rx_packets = 0;
        uint64_t tx_packets = 0;
        uint64_t handshakes = 0;
        size_t active_peers = 0;
    };
    Stats stats() const;

private:
    // Event loop methods
    void udp_receive_loop();
    void tun_receive_loop();
    void timer_loop();

    // Packet handlers
    void handle_udp_packet(std::span<const uint8_t> data, const net::SocketAddress& from);
    void handle_tun_packet(std::span<const uint8_t> data);

    // Message handlers
    void handle_handshake_initiation(
        const protocol::HandshakeInitiation& msg,
        const net::SocketAddress& from
    );
    void handle_handshake_response(
        const protocol::HandshakeResponse& msg,
        const net::SocketAddress& from
    );
    void handle_cookie_reply(
        const protocol::CookieReply& msg,
        const net::SocketAddress& from
    );
    void handle_transport_data(
        const protocol::TransportData& msg,
        const net::SocketAddress& from
    );

    // Send methods
    bool send_handshake_initiation(protocol::Peer& peer);
    bool send_handshake_response(protocol::Peer& peer, uint32_t receiver_index);
    bool send_transport_data(protocol::Peer& peer, std::span<const uint8_t> plaintext);
    bool send_keepalive(protocol::Peer& peer);

    // Peer lookup
    std::shared_ptr<protocol::Peer> find_peer_by_public_key(const crypto::PublicKey& key);
    std::shared_ptr<protocol::Peer> find_peer_by_session_index(uint32_t index);
    std::shared_ptr<protocol::Peer> find_peer_for_ip(const net::IpAddress& ip);

    // Session index management
    void register_session_index(uint32_t index, std::shared_ptr<protocol::Peer> peer);
    void unregister_session_index(uint32_t index);

    // Configuration
    crypto::Curve25519KeyPair keypair_;
    RuntimeConfig config_;

    // Network
    net::UdpSocket udp_socket_;
    net::TunDevice tun_device_;

    // Cookie handling
    crypto::CookieGenerator cookie_generator_;

    // Peers
    mutable std::shared_mutex peers_mutex_;
    std::vector<std::shared_ptr<protocol::Peer>> peers_;
    std::unordered_map<uint32_t, std::weak_ptr<protocol::Peer>> session_index_map_;

    // Thread pool
    std::unique_ptr<ThreadPool> thread_pool_;

    // Worker threads
    std::thread udp_thread_;
    std::thread tun_thread_;
    std::thread timer_thread_;

    // State
    std::atomic<bool> running_{false};

    // Statistics
    mutable std::mutex stats_mutex_;
    Stats stats_;
};

} // namespace vpn::core
