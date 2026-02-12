#include "vpn/mesh/beacon.hpp"
#include "vpn/util/logger.hpp"
#include "vpn/util/base64.hpp"
#include <cstring>
#include <random>

namespace vpn::mesh {

Beacon::Beacon(const BeaconConfig& config)
    : config_(config)
    , local_node_id_(derive_node_id(config.keypair.public_key()))
    , cookie_generator_(config.keypair.public_key())
    , routing_table_(local_node_id_)
{
    size_t num_threads = config.num_threads > 0 ? config.num_threads : std::thread::hardware_concurrency();
    thread_pool_ = std::make_unique<core::ThreadPool>(num_threads);
}

Beacon::~Beacon() {
    stop();
}

void Beacon::run() {
    LOG_INFO("Starting mesh beacon on port {}", config_.listen_port);
    LOG_INFO("Network: {}", config_.network_name);

    // Bind UDP socket
    if (!udp_socket_.bind_any(config_.listen_port)) {
        LOG_ERROR("Failed to bind UDP socket to port {}", config_.listen_port);
        return;
    }

    udp_socket_.set_nonblocking(true);
    LOG_INFO("Beacon UDP socket bound successfully");

    running_.store(true, std::memory_order_release);

    // Start worker threads
    udp_thread_ = std::thread(&Beacon::udp_receive_loop, this);
    timer_thread_ = std::thread(&Beacon::timer_loop, this);

    LOG_INFO("Beacon running, public key: {}", config_.keypair.public_key_base64());

    // Wait for threads
    if (udp_thread_.joinable()) udp_thread_.join();
    if (timer_thread_.joinable()) timer_thread_.join();

    LOG_INFO("Beacon stopped");
}

void Beacon::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    LOG_INFO("Stopping beacon...");
    udp_socket_.close();

    if (thread_pool_) {
        thread_pool_->stop();
    }

    if (udp_thread_.joinable()) udp_thread_.join();
    if (timer_thread_.joinable()) timer_thread_.join();
}

size_t Beacon::node_count() const {
    std::shared_lock lock(nodes_mutex_);
    return registered_nodes_.size();
}

void Beacon::udp_receive_loop() {
    std::vector<uint8_t> buffer(net::UdpSocket::MAX_PACKET_SIZE);

    while (running_.load(std::memory_order_relaxed)) {
        net::SocketAddress from;
        ssize_t n = udp_socket_.recv_from_into(buffer, from);

        if (n <= 0) {
            if (n == 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
            continue;
        }

        auto packet_data = std::vector<uint8_t>(buffer.begin(), buffer.begin() + n);
        auto from_addr = from;

        thread_pool_->submit_detached([this, packet_data = std::move(packet_data), from_addr]() {
            handle_udp_packet(packet_data, from_addr);
        });
    }
}

void Beacon::timer_loop() {
    auto last_expire = std::chrono::steady_clock::now();
    auto last_dht_expire = std::chrono::steady_clock::now();

    while (running_.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto now = std::chrono::steady_clock::now();

        // Expire stale nodes every 30 seconds
        if (now - last_expire >= std::chrono::seconds(30)) {
            expire_nodes();
            last_expire = now;
        }

        // Expire DHT entries every 60 seconds
        if (now - last_dht_expire >= std::chrono::seconds(60)) {
            dht_store_.expire();
            last_dht_expire = now;
        }

        // Process peer timers
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
                case protocol::TimerEvent::PersistentKeepalive: {
                    // Send keepalive
                    auto session = peer->current_session();
                    if (session && !session->is_expired()) {
                        auto endpoint = peer->endpoint();
                        if (endpoint) {
                            auto ciphertext = session->encrypt({});
                            protocol::TransportData msg;
                            msg.receiver_index = session->remote_index();
                            msg.counter = session->next_send_counter();
                            msg.encrypted_packet = std::move(ciphertext);
                            auto data = msg.serialize();
                            udp_socket_.send_to(data, *endpoint);
                        }
                    }
                    break;
                }
                case protocol::TimerEvent::ZeroKeys:
                    peer->set_current_session(nullptr);
                    break;
            }
        }
    }
}

void Beacon::handle_udp_packet(std::span<const uint8_t> data, const net::SocketAddress& from) {
    auto msg_type = protocol::get_message_type(data);
    if (!msg_type) return;

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

        case protocol::MessageType::TransportData:
            if (auto msg = protocol::TransportData::parse(data)) {
                handle_transport_data(*msg, from);
            }
            break;

        default:
            break;
    }
}

void Beacon::handle_handshake_initiation(
    const protocol::HandshakeInitiation& msg,
    const net::SocketAddress& from
) {
    LOG_DEBUG("Beacon: handshake initiation from {}", from.to_string());

    auto hs = crypto::NoiseHandshake::create_responder(config_.keypair);
    auto result = hs.process_initiation(msg.serialize());
    if (!result) {
        LOG_DEBUG("Beacon: failed to process handshake initiation");
        return;
    }

    // Check if we know this peer, or create a new one
    auto peer = find_peer_by_public_key(result->initiator_public_key);
    if (!peer) {
        // Create new peer entry for this connecting node
        protocol::PeerConfig peer_config;
        peer_config.public_key = result->initiator_public_key;
        peer_config.endpoint = from;
        // Allow all IPs from mesh nodes (we route based on mesh, not WG AllowedIPs)
        peer_config.allowed_ips.push_back(net::Subnet(net::IpAddress(net::IPv4Address(0, 0, 0, 0)), 0));

        peer = std::make_shared<protocol::Peer>(peer_config);
        std::unique_lock lock(peers_mutex_);
        peers_.push_back(peer);
    }

    // Update peer endpoint
    peer->set_endpoint(from);

    // Complete handshake
    auto session_keys = hs.finalize();
    if (!session_keys) {
        LOG_DEBUG("Beacon: failed to finalize handshake");
        return;
    }

    auto session = std::make_shared<protocol::Session>(
        session_keys->send_key,
        session_keys->receive_key,
        session_keys->sender_index,
        session_keys->receiver_index
    );

    register_session_index(session_keys->sender_index, peer);
    peer->rotate_session(session);
    peer->timers().handshake_complete();

    // Send response
    if (udp_socket_.send_to(result->message, from)) {
        LOG_INFO("Beacon: handshake completed with {}", from.to_string());
    }
}

void Beacon::handle_handshake_response(
    const protocol::HandshakeResponse& msg,
    const net::SocketAddress& from
) {
    auto peer = find_peer_by_session_index(msg.receiver_index);
    if (!peer) return;

    auto session_keys = peer->handshake().process_response(msg.serialize());
    if (!session_keys) return;

    auto session = std::make_shared<protocol::Session>(
        session_keys->send_key,
        session_keys->receive_key,
        session_keys->sender_index,
        session_keys->receiver_index
    );

    register_session_index(session_keys->sender_index, peer);
    peer->rotate_session(session);
    peer->set_endpoint(from);
    peer->timers().handshake_complete();
}

void Beacon::handle_transport_data(
    const protocol::TransportData& msg,
    const net::SocketAddress& from
) {
    auto peer = find_peer_by_session_index(msg.receiver_index);
    if (!peer) return;

    auto session = peer->session_by_index(msg.receiver_index);
    if (!session) return;

    auto plaintext = session->decrypt(msg.encrypted_packet, msg.counter);
    if (!plaintext) return;

    peer->add_rx_bytes(msg.encrypted_packet.size());
    peer->timers().data_received();

    auto current_endpoint = peer->endpoint();
    if (!current_endpoint || *current_endpoint != from) {
        peer->set_endpoint(from);
    }

    if (plaintext->empty()) return;  // Keepalive

    // Check if this is a mesh message
    if (is_mesh_message(*plaintext)) {
        handle_mesh_message(*plaintext, peer, from);
    }
}

void Beacon::handle_mesh_message(
    std::span<const uint8_t> plaintext,
    std::shared_ptr<protocol::Peer> peer,
    const net::SocketAddress& from
) {
    auto header = parse_mesh_header(plaintext);
    if (!header) return;

    auto payload = plaintext.subspan(MESH_HEADER_SIZE, header->payload_length);

    switch (header->type) {
        case MeshMessageType::Register:
            if (auto msg = MeshRegister::parse(payload)) {
                handle_register(*msg, peer);
            }
            break;

        case MeshMessageType::PeerListRequest:
            if (auto msg = MeshPeerListRequest::parse(payload)) {
                handle_peer_list_request(*msg, peer);
            }
            break;

        case MeshMessageType::FindNode:
            if (auto msg = MeshFindNode::parse(payload)) {
                handle_find_node(*msg, peer);
            }
            break;

        case MeshMessageType::FindValue:
            if (auto msg = MeshFindValue::parse(payload)) {
                handle_find_value(*msg, peer);
            }
            break;

        case MeshMessageType::Store:
            if (auto msg = MeshStore::parse(payload)) {
                handle_store(*msg, peer);
            }
            break;

        case MeshMessageType::PunchRequest:
            if (auto msg = MeshPunchRequest::parse(payload)) {
                handle_punch_request(*msg, peer);
            }
            break;

        default:
            LOG_DEBUG("Beacon: unknown mesh message type {}", static_cast<int>(header->type));
            break;
    }
}

void Beacon::handle_register(const MeshRegister& msg, std::shared_ptr<protocol::Peer> peer) {
    LOG_INFO("Beacon: registration from network '{}', VPN IP {}",
             msg.node_info.network_name, msg.node_info.vpn_ipv4.to_string());

    // Validate network name
    if (msg.node_info.network_name != config_.network_name) {
        MeshRegisterAck ack;
        ack.accepted = false;
        ack.assigned_node_id = {};
        ack.message = "Network name mismatch";
        send_mesh_message(*peer, ack.serialize());
        return;
    }

    // Validate network secret
    if (!validate_network_secret(msg.network_secret)) {
        MeshRegisterAck ack;
        ack.accepted = false;
        ack.assigned_node_id = {};
        ack.message = "Invalid network secret";
        send_mesh_message(*peer, ack.serialize());
        return;
    }

    // Check max peers
    if (node_count() >= config_.max_peers) {
        MeshRegisterAck ack;
        ack.accepted = false;
        ack.assigned_node_id = {};
        ack.message = "Maximum peers reached";
        send_mesh_message(*peer, ack.serialize());
        return;
    }

    auto node_id = derive_node_id(msg.node_info.public_key);

    // Store in registry
    {
        std::unique_lock lock(nodes_mutex_);
        auto key = util::base64_encode(msg.node_info.public_key.span());
        auto now = std::chrono::steady_clock::now();
        registered_nodes_[key] = RegisteredNode{
            msg.node_info,
            peer,
            now,
            now
        };
        registered_nodes_[key].info.node_id = node_id;
    }

    // Add to Kademlia routing table
    auto info_copy = msg.node_info;
    info_copy.node_id = node_id;
    routing_table_.add_or_update(info_copy);

    // Send ack
    MeshRegisterAck ack;
    ack.accepted = true;
    ack.assigned_node_id = node_id;
    ack.message = "Registered successfully";
    send_mesh_message(*peer, ack.serialize());

    // Send current peer list
    MeshPeerList peer_list;
    {
        std::shared_lock lock(nodes_mutex_);
        for (const auto& [key, node] : registered_nodes_) {
            if (node.info.public_key != msg.node_info.public_key) {
                peer_list.peers.push_back(node.info);
            }
        }
    }

    if (!peer_list.peers.empty()) {
        send_mesh_message(*peer, peer_list.serialize());
    }

    // Notify existing peers about the new node
    {
        std::shared_lock lock(nodes_mutex_);
        for (const auto& [key, node] : registered_nodes_) {
            if (node.info.public_key != msg.node_info.public_key && node.peer) {
                MeshPeerList new_peer_notification;
                new_peer_notification.peers.push_back(info_copy);
                send_mesh_message(*node.peer, new_peer_notification.serialize());
            }
        }
    }

    LOG_INFO("Beacon: node registered, total nodes: {}", node_count());
}

void Beacon::handle_peer_list_request(
    const MeshPeerListRequest& msg,
    std::shared_ptr<protocol::Peer> peer
) {
    MeshPeerList peer_list;
    {
        std::shared_lock lock(nodes_mutex_);
        for (const auto& [key, node] : registered_nodes_) {
            if (node.info.timestamp > msg.since_timestamp) {
                peer_list.peers.push_back(node.info);
            }
        }
    }
    send_mesh_message(*peer, peer_list.serialize());
}

void Beacon::handle_find_node(const MeshFindNode& msg, std::shared_ptr<protocol::Peer> peer) {
    auto closest = routing_table_.find_closest(msg.target, K_BUCKET_SIZE);

    MeshFindNodeResponse response;
    response.sender_id = local_node_id_;
    response.closest_nodes = closest;
    send_mesh_message(*peer, response.serialize());
}

void Beacon::handle_find_value(const MeshFindValue& msg, std::shared_ptr<protocol::Peer> peer) {
    auto value = dht_store_.find(msg.key);

    MeshFindValueResponse response;
    response.sender_id = local_node_id_;

    if (value) {
        response.found = true;
        response.value = *value;
    } else {
        response.found = false;
        // Return closest nodes to the key
        NodeId key_id;
        if (msg.key.size() >= NODE_ID_SIZE) {
            std::memcpy(key_id.data(), msg.key.data(), NODE_ID_SIZE);
        } else {
            key_id = {};
            std::memcpy(key_id.data(), msg.key.data(), msg.key.size());
        }
        response.closest_nodes = routing_table_.find_closest(key_id, K_BUCKET_SIZE);
    }

    send_mesh_message(*peer, response.serialize());
}

void Beacon::handle_store(const MeshStore& msg, std::shared_ptr<protocol::Peer> peer) {
    dht_store_.store(msg.key, msg.value, msg.sender_id, msg.ttl_seconds);
    LOG_DEBUG("Beacon: stored DHT value, key size={}, ttl={}s", msg.key.size(), msg.ttl_seconds);
}

void Beacon::handle_punch_request(const MeshPunchRequest& msg, std::shared_ptr<protocol::Peer> requester_peer) {
    // Find the target node
    std::shared_ptr<protocol::Peer> target_peer;
    NodeInfo requester_info;

    {
        std::shared_lock lock(nodes_mutex_);

        // Find requester info
        for (const auto& [key, node] : registered_nodes_) {
            if (node.peer == requester_peer) {
                requester_info = node.info;
                break;
            }
        }

        // Find target
        for (const auto& [key, node] : registered_nodes_) {
            if (node.info.public_key == msg.target_public_key) {
                target_peer = node.peer;
                break;
            }
        }
    }

    if (!target_peer) {
        LOG_DEBUG("Beacon: punch request for unknown target");
        return;
    }

    // Forward punch notification to target
    MeshPunchNotify notify;
    notify.requester_info = requester_info;

    // Generate a random nonce for coordination
    std::random_device rd;
    std::mt19937_64 gen(rd());
    notify.punch_nonce = gen();

    send_mesh_message(*target_peer, notify.serialize());

    // Also notify the requester about the target's endpoints
    MeshPunchNotify requester_notify;
    {
        std::shared_lock lock(nodes_mutex_);
        for (const auto& [key, node] : registered_nodes_) {
            if (node.info.public_key == msg.target_public_key) {
                requester_notify.requester_info = node.info;
                break;
            }
        }
    }
    requester_notify.punch_nonce = notify.punch_nonce;
    send_mesh_message(*requester_peer, requester_notify.serialize());

    LOG_DEBUG("Beacon: forwarded punch request");
}

bool Beacon::send_mesh_message(protocol::Peer& peer, const std::vector<uint8_t>& mesh_data) {
    auto session = peer.current_session();
    if (!session || session->is_expired()) {
        return false;
    }

    auto endpoint = peer.endpoint();
    if (!endpoint) return false;

    auto ciphertext = session->encrypt(mesh_data);

    protocol::TransportData msg;
    msg.receiver_index = session->remote_index();
    msg.counter = session->next_send_counter();
    msg.encrypted_packet = std::move(ciphertext);

    auto data = msg.serialize();
    return udp_socket_.send_to(data, *endpoint);
}

bool Beacon::send_handshake_initiation(protocol::Peer& peer) {
    peer.reset_handshake(config_.keypair);

    auto result = peer.handshake().create_initiation();
    if (!result) return false;

    auto endpoint = peer.endpoint();
    if (!endpoint) return false;

    register_session_index(result->sender_index, find_peer_by_public_key(peer.public_key()));
    peer.timers().handshake_initiated();

    return udp_socket_.send_to(result->message, *endpoint);
}

bool Beacon::validate_network_secret(const std::vector<uint8_t>& secret) const {
    if (secret.size() != config_.network_secret.size()) return false;

    // Constant-time comparison
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < secret.size(); ++i) {
        diff |= secret[i] ^ config_.network_secret[i];
    }
    return diff == 0;
}

void Beacon::expire_nodes() {
    auto now = std::chrono::steady_clock::now();
    std::vector<std::string> expired;

    {
        std::shared_lock lock(nodes_mutex_);
        for (const auto& [key, node] : registered_nodes_) {
            if (now - node.last_seen > config_.peer_expiry) {
                expired.push_back(key);
            }
        }
    }

    if (!expired.empty()) {
        std::unique_lock lock(nodes_mutex_);
        for (const auto& key : expired) {
            auto it = registered_nodes_.find(key);
            if (it != registered_nodes_.end()) {
                routing_table_.remove(it->second.info.node_id);
                registered_nodes_.erase(it);
            }
        }
        LOG_INFO("Beacon: expired {} stale nodes, {} remaining", expired.size(), registered_nodes_.size());
    }
}

std::shared_ptr<protocol::Peer> Beacon::find_peer_by_public_key(const crypto::PublicKey& key) {
    std::shared_lock lock(peers_mutex_);
    for (auto& peer : peers_) {
        if (peer->public_key() == key) {
            return peer;
        }
    }
    return nullptr;
}

std::shared_ptr<protocol::Peer> Beacon::find_peer_by_session_index(uint32_t index) {
    std::shared_lock lock(peers_mutex_);
    auto it = session_index_map_.find(index);
    if (it != session_index_map_.end()) {
        return it->second.lock();
    }
    return nullptr;
}

void Beacon::register_session_index(uint32_t index, std::shared_ptr<protocol::Peer> peer) {
    std::unique_lock lock(peers_mutex_);
    session_index_map_[index] = peer;
}

} // namespace vpn::mesh
