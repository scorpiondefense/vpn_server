#include "vpn/mesh/mesh_node.hpp"
#include "vpn/core/server.hpp"
#include "vpn/util/logger.hpp"
#include "vpn/util/base64.hpp"
#include <random>
#include <cstring>

namespace vpn::mesh {

MeshNode::MeshNode(const MeshNodeConfig& config, const crypto::Curve25519KeyPair& keypair,
                   core::Server& server)
    : config_(config)
    , keypair_(keypair)
    , local_node_id_(derive_node_id(keypair.public_key()))
    , server_(server)
    , routing_table_(local_node_id_)
{
    auto now = std::chrono::steady_clock::now();
    last_ping_time_ = now;
    last_health_check_ = now;
    last_dht_refresh_ = now;
    last_register_attempt_ = now - std::chrono::seconds(30);  // Allow immediate first attempt
    last_peer_list_request_ = now - std::chrono::seconds(60);
}

void MeshNode::start() {
    LOG_INFO("Mesh node starting, network: {}", config_.network_name);
    LOG_INFO("Mesh node ID: {:02x}{:02x}{:02x}{:02x}...",
             local_node_id_[0], local_node_id_[1], local_node_id_[2], local_node_id_[3]);

    // Add beacon as a WireGuard peer
    core::RuntimeConfig::ResolvedPeer beacon_peer;
    beacon_peer.public_key = config_.beacon_public_key;
    beacon_peer.endpoint = config_.beacon_address;
    // Beacon gets 0.0.0.0/0 for AllowedIPs (we use mesh routing, not WG AllowedIPs filtering)
    beacon_peer.allowed_ips.push_back(net::Subnet(net::IpAddress(net::IPv4Address(0, 0, 0, 0)), 0));
    beacon_peer.persistent_keepalive = std::chrono::seconds(25);

    server_.add_peer(beacon_peer);

    LOG_INFO("Mesh: beacon peer added at {}", config_.beacon_address.to_string());
}

std::vector<uint8_t> MeshNode::build_register_message() const {
    MeshRegister reg;
    reg.node_info.public_key = keypair_.public_key();
    reg.node_info.node_id = local_node_id_;
    reg.node_info.vpn_ipv4 = config_.vpn_ipv4;
    reg.node_info.vpn_ipv6 = config_.vpn_ipv6;
    reg.node_info.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
    reg.node_info.network_name = config_.network_name;
    reg.network_secret = config_.network_secret;

    return reg.serialize();
}

void MeshNode::handle_mesh_message(std::span<const uint8_t> data,
                                     const crypto::PublicKey& from_peer_key) {
    auto header = parse_mesh_header(data);
    if (!header) return;

    auto payload = data.subspan(MESH_HEADER_SIZE, header->payload_length);

    switch (header->type) {
        case MeshMessageType::RegisterAck:
            if (auto msg = MeshRegisterAck::parse(payload)) {
                handle_register_ack(*msg);
            }
            break;

        case MeshMessageType::PeerList:
            if (auto msg = MeshPeerList::parse(payload)) {
                handle_peer_list(*msg);
            }
            break;

        case MeshMessageType::MeshPing:
            if (auto msg = MeshPing::parse(payload)) {
                handle_mesh_ping(*msg, from_peer_key);
            }
            break;

        case MeshMessageType::MeshPong:
            if (auto msg = MeshPong::parse(payload)) {
                handle_mesh_pong(*msg, from_peer_key);
            }
            break;

        case MeshMessageType::FindNode:
            if (auto msg = MeshFindNode::parse(payload)) {
                handle_find_node(*msg, from_peer_key);
            }
            break;

        case MeshMessageType::FindNodeResponse:
            if (auto msg = MeshFindNodeResponse::parse(payload)) {
                handle_find_node_response(*msg);
            }
            break;

        case MeshMessageType::FindValueResponse:
            if (auto msg = MeshFindValueResponse::parse(payload)) {
                handle_find_value_response(*msg);
            }
            break;

        case MeshMessageType::PunchNotify:
            if (auto msg = MeshPunchNotify::parse(payload)) {
                handle_punch_notify(*msg);
            }
            break;

        case MeshMessageType::RouteAdvertise:
            if (auto msg = MeshRouteAdvertise::parse(payload)) {
                handle_route_advertise(*msg, from_peer_key);
            }
            break;

        default:
            LOG_DEBUG("Mesh: unknown message type {}", static_cast<int>(header->type));
            break;
    }
}

void MeshNode::mesh_timer_tick() {
    auto now = std::chrono::steady_clock::now();

    // Register with beacon if not yet registered
    if (!registered_ && now - last_register_attempt_ >= std::chrono::seconds(5)) {
        last_register_attempt_ = now;
        auto reg_msg = build_register_message();
        send_to_beacon(reg_msg);
        LOG_DEBUG("Mesh: sent registration to beacon");
    }

    // Periodic peer list request (every 60 seconds)
    if (registered_ && now - last_peer_list_request_ >= std::chrono::seconds(60)) {
        last_peer_list_request_ = now;
        request_peer_list_update();
    }

    // Ping peers (every ping_interval)
    if (now - last_ping_time_ >= config_.ping_interval) {
        last_ping_time_ = now;
        ping_peers();
    }

    // Health check (every 10 seconds)
    if (now - last_health_check_ >= std::chrono::seconds(10)) {
        last_health_check_ = now;
        check_peer_health();
    }

    // DHT bucket refresh (every 15 minutes)
    if (now - last_dht_refresh_ >= std::chrono::minutes(15)) {
        last_dht_refresh_ = now;
        refresh_dht_buckets();
    }

    // Expire DHT entries
    dht_store_.expire();
}

void MeshNode::handle_register_ack(const MeshRegisterAck& msg) {
    if (msg.accepted) {
        registered_ = true;
        LOG_INFO("Mesh: registered with beacon - {}", msg.message);
    } else {
        LOG_ERROR("Mesh: registration rejected - {}", msg.message);
    }
}

void MeshNode::handle_peer_list(const MeshPeerList& msg) {
    LOG_INFO("Mesh: received peer list with {} peers", msg.peers.size());

    for (const auto& peer_info : msg.peers) {
        // Don't add ourselves
        if (peer_info.public_key == keypair_.public_key()) continue;

        // Add to routing table
        routing_table_.add_or_update(peer_info);

        // Connect if auto_connect enabled
        if (config_.auto_connect) {
            connect_to_peer(peer_info);
        }
    }
}

void MeshNode::handle_mesh_ping(const MeshPing& msg, const crypto::PublicKey& from) {
    // Respond with pong
    MeshPong pong;
    pong.nonce = msg.nonce;
    pong.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    );

    send_to_peer(from, pong.serialize());
}

void MeshNode::handle_mesh_pong(const MeshPong& msg, const crypto::PublicKey& from) {
    auto key = peer_key_str(from);
    std::lock_guard lock(peers_mutex_);

    auto it = mesh_peers_.find(key);
    if (it != mesh_peers_.end()) {
        auto now = std::chrono::steady_clock::now();
        it->second.last_pong_received = now;
        it->second.missed_pings = 0;

        // Calculate RTT
        if (it->second.last_ping_nonce == msg.nonce) {
            auto rtt = std::chrono::duration_cast<std::chrono::microseconds>(
                now - it->second.last_ping_sent);
            it->second.rtt = rtt;
            LOG_DEBUG("Mesh: pong from peer, RTT={}us", rtt.count());
        }
    }
}

void MeshNode::handle_find_node(const MeshFindNode& msg, const crypto::PublicKey& from) {
    auto closest = routing_table_.find_closest(msg.target, K_BUCKET_SIZE);

    MeshFindNodeResponse response;
    response.sender_id = local_node_id_;
    response.closest_nodes = closest;

    send_to_peer(from, response.serialize());
}

void MeshNode::handle_find_node_response(const MeshFindNodeResponse& msg) {
    // Add discovered nodes to routing table
    for (const auto& node : msg.closest_nodes) {
        routing_table_.add_or_update(node);

        // Optionally connect to newly discovered peers
        if (config_.auto_connect) {
            auto key = peer_key_str(node.public_key);
            std::lock_guard lock(peers_mutex_);
            if (mesh_peers_.find(key) == mesh_peers_.end()) {
                // Unlock before connecting since connect_to_peer may also lock
            }
        }
    }
}

void MeshNode::handle_find_value_response(const MeshFindValueResponse& msg) {
    if (msg.found) {
        LOG_DEBUG("Mesh: FIND_VALUE response - value found, size={}", msg.value.size());
    } else {
        // Add closer nodes to routing table
        for (const auto& node : msg.closest_nodes) {
            routing_table_.add_or_update(node);
        }
    }
}

void MeshNode::handle_punch_notify(const MeshPunchNotify& msg) {
    LOG_INFO("Mesh: punch notification for peer at {}",
             msg.requester_info.endpoints.empty() ? "unknown" :
             msg.requester_info.endpoints[0].to_string());

    // Try to connect to the peer directly
    connect_to_peer(msg.requester_info);
}

void MeshNode::handle_route_advertise(const MeshRouteAdvertise& msg, const crypto::PublicKey& from) {
    LOG_DEBUG("Mesh: route advertisement with {} routes from peer", msg.routes.size());
    // TODO: Integrate with routing table for subnet-level routing
}

void MeshNode::ping_peers() {
    std::lock_guard lock(peers_mutex_);
    auto now = std::chrono::steady_clock::now();

    for (auto& [key, peer] : mesh_peers_) {
        if (!peer.connected) continue;

        MeshPing ping;
        ping.nonce = next_ping_nonce_++;
        ping.timestamp = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                now.time_since_epoch()
            ).count()
        );

        peer.last_ping_nonce = ping.nonce;
        peer.last_ping_sent = now;
        peer.missed_pings++;

        send_to_peer(peer.info.public_key, ping.serialize());
    }
}

void MeshNode::check_peer_health() {
    std::vector<crypto::PublicKey> to_remove;

    {
        std::lock_guard lock(peers_mutex_);
        for (auto& [key, peer] : mesh_peers_) {
            if (peer.missed_pings >= config_.max_missed_pings) {
                LOG_WARNING("Mesh: peer {} unresponsive ({} missed pings), removing",
                           peer.info.vpn_ipv4.to_string(), peer.missed_pings);
                to_remove.push_back(peer.info.public_key);
            }
        }
    }

    for (const auto& key : to_remove) {
        auto key_str = peer_key_str(key);
        {
            std::lock_guard lock(peers_mutex_);
            mesh_peers_.erase(key_str);
        }
        server_.remove_peer(key);
        routing_table_.remove(derive_node_id(key));
    }
}

void MeshNode::refresh_dht_buckets() {
    auto stale = routing_table_.stale_buckets();
    for (int bucket_idx : stale) {
        // Generate random ID in this bucket's range and do FIND_NODE
        auto random_id = RoutingTable::random_id_in_bucket(local_node_id_, bucket_idx);

        MeshFindNode find_msg;
        find_msg.target = random_id;
        find_msg.sender_id = local_node_id_;

        // Send to beacon
        send_to_beacon(find_msg.serialize());
    }
}

void MeshNode::request_peer_list_update() {
    MeshPeerListRequest req;
    // Request peers updated in the last 2 minutes
    auto since = std::chrono::system_clock::now() - std::chrono::seconds(120);
    req.since_timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            since.time_since_epoch()
        ).count()
    );

    send_to_beacon(req.serialize());
}

void MeshNode::connect_to_peer(const NodeInfo& info) {
    auto key = peer_key_str(info.public_key);

    {
        std::lock_guard lock(peers_mutex_);
        // Already tracking this peer
        if (mesh_peers_.find(key) != mesh_peers_.end()) return;

        // Check max peers
        if (mesh_peers_.size() >= config_.max_peers) return;

        MeshPeer mesh_peer;
        mesh_peer.info = info;
        mesh_peer.connected = true;
        mesh_peer.last_pong_received = std::chrono::steady_clock::now();
        mesh_peers_[key] = mesh_peer;
    }

    // Add as WireGuard peer in the server
    core::RuntimeConfig::ResolvedPeer wg_peer;
    wg_peer.public_key = info.public_key;

    // Use the first endpoint if available
    if (!info.endpoints.empty()) {
        wg_peer.endpoint = info.endpoints[0];
    }

    // AllowedIPs = their VPN IP /32
    wg_peer.allowed_ips.push_back(net::Subnet(info.vpn_ipv4, 32));
    if (info.vpn_ipv6) {
        wg_peer.allowed_ips.push_back(net::Subnet(*info.vpn_ipv6, 128));
    }

    wg_peer.persistent_keepalive = std::chrono::seconds(25);

    server_.add_peer(wg_peer);

    LOG_INFO("Mesh: connected to peer at VPN IP {}", info.vpn_ipv4.to_string());
}

bool MeshNode::send_to_peer(const crypto::PublicKey& peer_key,
                             const std::vector<uint8_t>& mesh_data) {
    // The Server will handle sending this as WireGuard transport data.
    // We need to find the peer and use the server's send method.
    return server_.send_mesh_data(peer_key, mesh_data);
}

bool MeshNode::send_to_beacon(const std::vector<uint8_t>& mesh_data) {
    return send_to_peer(config_.beacon_public_key, mesh_data);
}

std::vector<MeshPeer> MeshNode::connected_peers() const {
    std::lock_guard lock(peers_mutex_);
    std::vector<MeshPeer> result;
    for (const auto& [key, peer] : mesh_peers_) {
        if (peer.connected) {
            result.push_back(peer);
        }
    }
    return result;
}

MeshNode::MeshStats MeshNode::stats() const {
    MeshStats s;
    {
        std::lock_guard lock(peers_mutex_);
        s.total_peers = mesh_peers_.size();
        for (const auto& [key, peer] : mesh_peers_) {
            if (peer.connected) s.connected_peers++;
        }
    }
    s.routing_table_size = routing_table_.node_count();
    s.dht_entries = dht_store_.size();
    return s;
}

std::string MeshNode::peer_key_str(const crypto::PublicKey& key) {
    return util::base64_encode(key.span());
}

} // namespace vpn::mesh
