#include "vpn/core/server.hpp"
#include "vpn/util/logger.hpp"
#include <cstring>

namespace vpn::core {

Server::Server(const RuntimeConfig& config)
    : keypair_(config.keypair)
    , config_(config)
    , cookie_generator_(keypair_.public_key())
{
    // Create thread pool
    thread_pool_ = std::make_unique<ThreadPool>(config.num_threads);

    // Add configured peers
    for (const auto& peer_config : config.peers) {
        add_peer(peer_config);
    }
}

Server::~Server() {
    stop();
}

void Server::run() {
    LOG_INFO("Starting WireGuard server on port {}", config_.listen_port);

    // Bind UDP socket
    if (!udp_socket_.bind_any(config_.listen_port)) {
        LOG_ERROR("Failed to bind UDP socket to port {}", config_.listen_port);
        return;
    }

    udp_socket_.set_nonblocking(true);
    udp_socket_.set_recv_buffer_size(config_.recv_buffer_size);
    udp_socket_.set_send_buffer_size(config_.send_buffer_size);

    LOG_INFO("UDP socket bound successfully");

    // Open TUN device
    if (!tun_device_.open(config_.interface_name)) {
        LOG_ERROR("Failed to open TUN device");
        return;
    }

    tun_device_.set_mtu(config_.mtu);
    tun_device_.set_nonblocking(true);

    // Configure addresses
    for (const auto& [addr, prefix] : config_.addresses) {
        if (addr.is_v4()) {
            tun_device_.add_address(addr.as_v4(), prefix);
        } else {
            tun_device_.add_address(addr.as_v6(), prefix);
        }
    }

    tun_device_.up();

    LOG_INFO("TUN device {} configured and up", tun_device_.name());

    running_.store(true, std::memory_order_release);

    // Start worker threads
    udp_thread_ = std::thread(&Server::udp_receive_loop, this);
    tun_thread_ = std::thread(&Server::tun_receive_loop, this);
    timer_thread_ = std::thread(&Server::timer_loop, this);

    LOG_INFO("Server running with {} worker threads", thread_pool_->num_threads());

    // Wait for threads
    if (udp_thread_.joinable()) udp_thread_.join();
    if (tun_thread_.joinable()) tun_thread_.join();
    if (timer_thread_.joinable()) timer_thread_.join();

    LOG_INFO("Server stopped");
}

void Server::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;  // Already stopped
    }

    LOG_INFO("Stopping server...");

    // Close sockets to unblock receive loops
    udp_socket_.close();
    tun_device_.close();

    // Stop thread pool
    if (thread_pool_) {
        thread_pool_->stop();
    }

    // Join threads
    if (udp_thread_.joinable()) udp_thread_.join();
    if (tun_thread_.joinable()) tun_thread_.join();
    if (timer_thread_.joinable()) timer_thread_.join();
}

void Server::add_peer(const RuntimeConfig::ResolvedPeer& peer_config) {
    protocol::PeerConfig config;
    config.public_key = peer_config.public_key;
    config.preshared_key = peer_config.preshared_key;
    config.endpoint = peer_config.endpoint;
    config.allowed_ips = peer_config.allowed_ips;
    config.persistent_keepalive = peer_config.persistent_keepalive;

    auto peer = std::make_shared<protocol::Peer>(config);

    std::unique_lock lock(peers_mutex_);
    peers_.push_back(peer);

    LOG_INFO("Added peer with allowed IPs: {}", peer_config.allowed_ips.empty() ? "none" : peer_config.allowed_ips[0].to_string());
}

void Server::remove_peer(const crypto::PublicKey& public_key) {
    std::unique_lock lock(peers_mutex_);
    peers_.erase(
        std::remove_if(peers_.begin(), peers_.end(),
            [&public_key](const auto& peer) {
                return peer->public_key() == public_key;
            }),
        peers_.end()
    );
}

Server::Stats Server::stats() const {
    std::lock_guard lock(stats_mutex_);
    return stats_;
}

void Server::udp_receive_loop() {
    std::vector<uint8_t> buffer(net::UdpSocket::MAX_PACKET_SIZE);

    while (running_.load(std::memory_order_relaxed)) {
        net::SocketAddress from;
        ssize_t n = udp_socket_.recv_from_into(buffer, from);

        if (n <= 0) {
            if (n == 0) {
                // Would block, use select/poll for efficiency
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
            continue;
        }

        // Process packet in thread pool
        auto packet_data = std::vector<uint8_t>(buffer.begin(), buffer.begin() + n);
        auto from_addr = from;

        thread_pool_->submit_detached([this, packet_data = std::move(packet_data), from_addr]() {
            handle_udp_packet(packet_data, from_addr);
        });
    }
}

void Server::tun_receive_loop() {
    std::vector<uint8_t> buffer(config_.mtu + 100);

    while (running_.load(std::memory_order_relaxed)) {
        ssize_t n = tun_device_.read_into(buffer);

        if (n <= 0) {
            if (n == 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
            continue;
        }

        // Process packet in thread pool
        auto packet_data = std::vector<uint8_t>(buffer.begin(), buffer.begin() + n);

        thread_pool_->submit_detached([this, packet_data = std::move(packet_data)]() {
            handle_tun_packet(packet_data);
        });
    }
}

void Server::timer_loop() {
    while (running_.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        std::shared_lock lock(peers_mutex_);
        for (auto& peer : peers_) {
            auto event = peer->timers().next_event();
            if (!event || event->second > std::chrono::milliseconds(0)) {
                continue;
            }

            switch (event->first) {
                case protocol::TimerEvent::RetransmitHandshake:
                case protocol::TimerEvent::NewHandshake:
                    send_handshake_initiation(*peer);
                    break;

                case protocol::TimerEvent::SendKeepalive:
                case protocol::TimerEvent::PersistentKeepalive:
                    send_keepalive(*peer);
                    break;

                case protocol::TimerEvent::ZeroKeys:
                    // Session expired, clear it
                    peer->set_current_session(nullptr);
                    break;
            }
        }
    }
}

void Server::handle_udp_packet(std::span<const uint8_t> data, const net::SocketAddress& from) {
    auto msg_type = protocol::get_message_type(data);
    if (!msg_type) {
        return;
    }

    {
        std::lock_guard lock(stats_mutex_);
        stats_.rx_bytes += data.size();
        stats_.rx_packets++;
    }

    switch (*msg_type) {
        case protocol::MessageType::HandshakeInitiation:
            if (auto msg = protocol::HandshakeInitiation::parse(data)) {
                handle_handshake_initiation(*msg, from);
            }
            break;

        case protocol::MessageType::HandshakeResponse:
            if (auto msg = protocol::HandshakeResponse::parse(data)) {
                handle_handshake_response(*msg, from);
            }
            break;

        case protocol::MessageType::CookieReply:
            if (auto msg = protocol::CookieReply::parse(data)) {
                handle_cookie_reply(*msg, from);
            }
            break;

        case protocol::MessageType::TransportData:
            if (auto msg = protocol::TransportData::parse(data)) {
                handle_transport_data(*msg, from);
            }
            break;
    }
}

void Server::handle_tun_packet(std::span<const uint8_t> data) {
    if (data.size() < 20) {
        return;  // Too small for IP header
    }

    // Parse destination IP from packet
    net::IpAddress dest_ip;
    uint8_t version = (data[0] >> 4) & 0x0F;

    if (version == 4) {
        // IPv4: destination is at offset 16
        dest_ip = net::IpAddress(net::IPv4Address(data[16], data[17], data[18], data[19]));
    } else if (version == 6) {
        // IPv6: destination is at offset 24
        if (data.size() < 40) return;
        std::array<uint8_t, 16> addr;
        std::memcpy(addr.data(), &data[24], 16);
        dest_ip = net::IpAddress(net::IPv6Address(addr));
    } else {
        return;  // Unknown IP version
    }

    // Find peer for destination
    auto peer = find_peer_for_ip(dest_ip);
    if (!peer) {
        LOG_DEBUG("No peer found for destination {}", dest_ip.to_string());
        return;
    }

    send_transport_data(*peer, data);
}

void Server::handle_handshake_initiation(
    const protocol::HandshakeInitiation& msg,
    const net::SocketAddress& from
) {
    LOG_DEBUG("Received handshake initiation from {}", from.to_string());

    // Create responder handshake to process the initiation
    auto hs = crypto::NoiseHandshake::create_responder(keypair_);

    auto result = hs.process_initiation(msg.serialize());
    if (!result) {
        LOG_DEBUG("Failed to process handshake initiation");
        return;
    }

    // Find the peer by their public key
    auto peer = find_peer_by_public_key(result->initiator_public_key);
    if (!peer) {
        LOG_DEBUG("Unknown peer public key in handshake");
        return;
    }

    // Check timestamp for replay protection
    if (hs.timestamp() && !peer->check_replay_timestamp(*hs.timestamp())) {
        LOG_DEBUG("Replay detected in handshake");
        return;
    }

    // Update peer endpoint
    peer->set_endpoint(from);

    // Complete handshake
    auto session_keys = hs.finalize();
    if (!session_keys) {
        LOG_DEBUG("Failed to finalize handshake");
        return;
    }

    // Create session
    auto session = std::make_shared<protocol::Session>(
        session_keys->send_key,
        session_keys->receive_key,
        session_keys->sender_index,
        session_keys->receiver_index
    );

    // Register session index
    register_session_index(session_keys->sender_index, peer);

    // Rotate session
    peer->rotate_session(session);
    peer->timers().handshake_complete();

    // Send response
    auto response_data = result->message;
    if (udp_socket_.send_to(response_data, from)) {
        std::lock_guard lock(stats_mutex_);
        stats_.tx_bytes += response_data.size();
        stats_.tx_packets++;
        stats_.handshakes++;
    }

    LOG_INFO("Handshake completed with peer from {}", from.to_string());
}

void Server::handle_handshake_response(
    const protocol::HandshakeResponse& msg,
    const net::SocketAddress& from
) {
    // Find peer by receiver index (our initiation's sender index)
    auto peer = find_peer_by_session_index(msg.receiver_index);
    if (!peer) {
        LOG_DEBUG("Unknown receiver index in handshake response");
        return;
    }

    auto session_keys = peer->handshake().process_response(msg.serialize());
    if (!session_keys) {
        LOG_DEBUG("Failed to process handshake response");
        return;
    }

    // Create session
    auto session = std::make_shared<protocol::Session>(
        session_keys->send_key,
        session_keys->receive_key,
        session_keys->sender_index,
        session_keys->receiver_index
    );

    // Register session index
    register_session_index(session_keys->sender_index, peer);

    peer->rotate_session(session);
    peer->set_endpoint(from);
    peer->timers().handshake_complete();

    {
        std::lock_guard lock(stats_mutex_);
        stats_.handshakes++;
    }

    LOG_INFO("Handshake response processed from {}", from.to_string());
}

void Server::handle_cookie_reply(
    const protocol::CookieReply& msg,
    const net::SocketAddress& from
) {
    // Find peer by receiver index
    auto peer = find_peer_by_session_index(msg.receiver_index);
    if (!peer) {
        return;
    }

    // TODO: Decrypt and store cookie for MAC2 computation
    // For now, we don't implement full cookie handling
}

void Server::handle_transport_data(
    const protocol::TransportData& msg,
    const net::SocketAddress& from
) {
    // Find peer by receiver index
    auto peer = find_peer_by_session_index(msg.receiver_index);
    if (!peer) {
        LOG_DEBUG("Unknown receiver index {} in transport data", msg.receiver_index);
        return;
    }

    auto session = peer->session_by_index(msg.receiver_index);
    if (!session) {
        return;
    }

    // Decrypt packet
    auto plaintext = session->decrypt(msg.encrypted_packet, msg.counter);
    if (!plaintext) {
        LOG_DEBUG("Failed to decrypt transport data");
        return;
    }

    peer->add_rx_bytes(msg.encrypted_packet.size());
    peer->timers().data_received();

    // Update endpoint if changed
    auto current_endpoint = peer->endpoint();
    if (!current_endpoint || *current_endpoint != from) {
        peer->set_endpoint(from);
    }

    // Empty packet is keepalive
    if (plaintext->empty()) {
        return;
    }

    // Write to TUN
    tun_device_.write(*plaintext);
}

bool Server::send_handshake_initiation(protocol::Peer& peer) {
    peer.reset_handshake(keypair_);

    auto result = peer.handshake().create_initiation();
    if (!result) {
        return false;
    }

    auto endpoint = peer.endpoint();
    if (!endpoint) {
        return false;
    }

    // Register our index for the response
    // Note: We need to convert raw pointer to shared_ptr properly
    // This is a simplification - in production, we'd need better handling
    register_session_index(result->sender_index, find_peer_by_public_key(peer.public_key()));

    peer.timers().handshake_initiated();

    if (udp_socket_.send_to(result->message, *endpoint)) {
        std::lock_guard lock(stats_mutex_);
        stats_.tx_bytes += result->message.size();
        stats_.tx_packets++;
        return true;
    }

    return false;
}

bool Server::send_handshake_response(protocol::Peer& peer, uint32_t receiver_index) {
    // Already handled in handle_handshake_initiation
    return true;
}

bool Server::send_transport_data(protocol::Peer& peer, std::span<const uint8_t> plaintext) {
    auto session = peer.current_session();
    if (!session || session->is_expired()) {
        // Need to initiate handshake
        if (!peer.timers().handshake_in_progress()) {
            send_handshake_initiation(peer);
        }
        return false;
    }

    auto endpoint = peer.endpoint();
    if (!endpoint) {
        return false;
    }

    // Build transport message
    uint64_t counter = session->next_send_counter();
    auto ciphertext = session->encrypt(plaintext);

    protocol::TransportData msg;
    msg.receiver_index = session->remote_index();
    msg.counter = counter;
    msg.encrypted_packet = std::move(ciphertext);

    auto data = msg.serialize();

    peer.add_tx_bytes(data.size());
    peer.timers().data_sent();

    if (udp_socket_.send_to(data, *endpoint)) {
        std::lock_guard lock(stats_mutex_);
        stats_.tx_bytes += data.size();
        stats_.tx_packets++;
        return true;
    }

    return false;
}

bool Server::send_keepalive(protocol::Peer& peer) {
    return send_transport_data(peer, {});
}

std::shared_ptr<protocol::Peer> Server::find_peer_by_public_key(const crypto::PublicKey& key) {
    std::shared_lock lock(peers_mutex_);
    for (auto& peer : peers_) {
        if (peer->public_key() == key) {
            return peer;
        }
    }
    return nullptr;
}

std::shared_ptr<protocol::Peer> Server::find_peer_by_session_index(uint32_t index) {
    std::shared_lock lock(peers_mutex_);
    auto it = session_index_map_.find(index);
    if (it != session_index_map_.end()) {
        return it->second.lock();
    }
    return nullptr;
}

std::shared_ptr<protocol::Peer> Server::find_peer_for_ip(const net::IpAddress& ip) {
    std::shared_lock lock(peers_mutex_);
    for (auto& peer : peers_) {
        if (peer->is_allowed_ip(ip)) {
            return peer;
        }
    }
    return nullptr;
}

void Server::register_session_index(uint32_t index, std::shared_ptr<protocol::Peer> peer) {
    std::unique_lock lock(peers_mutex_);
    session_index_map_[index] = peer;
}

void Server::unregister_session_index(uint32_t index) {
    std::unique_lock lock(peers_mutex_);
    session_index_map_.erase(index);
}

} // namespace vpn::core
