#include "vpn/mesh/mesh_message.hpp"
#include "vpn/crypto/blake2s.hpp"
#include <cstring>
#include <algorithm>

namespace vpn::mesh {

namespace {

template<typename T>
T read_le(const uint8_t* data) {
    T result = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        result |= static_cast<T>(data[i]) << (8 * i);
    }
    return result;
}

template<typename T>
void write_le(uint8_t* data, T value) {
    for (size_t i = 0; i < sizeof(T); ++i) {
        data[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
    }
}

void write_string(std::vector<uint8_t>& out, const std::string& str) {
    uint16_t len = static_cast<uint16_t>(str.size());
    size_t offset = out.size();
    out.resize(out.size() + 2 + len);
    write_le(&out[offset], len);
    std::memcpy(&out[offset + 2], str.data(), len);
}

std::optional<std::string> read_string(std::span<const uint8_t> data, size_t& offset) {
    if (offset + 2 > data.size()) return std::nullopt;
    uint16_t len = read_le<uint16_t>(&data[offset]);
    offset += 2;
    if (offset + len > data.size()) return std::nullopt;
    std::string result(reinterpret_cast<const char*>(&data[offset]), len);
    offset += len;
    return result;
}

void write_bytes(std::vector<uint8_t>& out, std::span<const uint8_t> bytes) {
    uint16_t len = static_cast<uint16_t>(bytes.size());
    size_t offset = out.size();
    out.resize(out.size() + 2 + len);
    write_le(&out[offset], len);
    std::memcpy(&out[offset + 2], bytes.data(), len);
}

std::optional<std::vector<uint8_t>> read_bytes(std::span<const uint8_t> data, size_t& offset) {
    if (offset + 2 > data.size()) return std::nullopt;
    uint16_t len = read_le<uint16_t>(&data[offset]);
    offset += 2;
    if (offset + len > data.size()) return std::nullopt;
    std::vector<uint8_t> result(data.begin() + offset, data.begin() + offset + len);
    offset += len;
    return result;
}

void write_socket_address(std::vector<uint8_t>& out, const net::SocketAddress& addr) {
    auto str = addr.to_string();
    write_string(out, str);
}

std::optional<net::SocketAddress> read_socket_address(std::span<const uint8_t> data, size_t& offset) {
    auto str = read_string(data, offset);
    if (!str) return std::nullopt;
    return net::SocketAddress::parse(*str);
}

void write_ip_address(std::vector<uint8_t>& out, const net::IpAddress& addr) {
    auto str = addr.to_string();
    write_string(out, str);
}

std::optional<net::IpAddress> read_ip_address(std::span<const uint8_t> data, size_t& offset) {
    auto str = read_string(data, offset);
    if (!str) return std::nullopt;
    return net::IpAddress::parse(*str);
}

void write_subnet(std::vector<uint8_t>& out, const net::Subnet& subnet) {
    auto str = subnet.to_string();
    write_string(out, str);
}

std::optional<net::Subnet> read_subnet(std::span<const uint8_t> data, size_t& offset) {
    auto str = read_string(data, offset);
    if (!str) return std::nullopt;
    return net::Subnet::parse(*str);
}

} // anonymous namespace

// --- NodeInfo ---

std::vector<uint8_t> NodeInfo::serialize() const {
    std::vector<uint8_t> out;
    out.reserve(256);

    // Public key (32 bytes)
    out.insert(out.end(), public_key.data(), public_key.data() + crypto::KEY_SIZE);

    // Node ID (20 bytes)
    out.insert(out.end(), node_id.begin(), node_id.end());

    // VPN IPv4
    write_ip_address(out, vpn_ipv4);

    // VPN IPv6 (optional: 1 byte flag + address if present)
    if (vpn_ipv6) {
        out.push_back(1);
        write_ip_address(out, *vpn_ipv6);
    } else {
        out.push_back(0);
    }

    // Endpoints count + endpoints
    uint8_t num_endpoints = static_cast<uint8_t>(std::min(endpoints.size(), size_t(255)));
    out.push_back(num_endpoints);
    for (uint8_t i = 0; i < num_endpoints; ++i) {
        write_socket_address(out, endpoints[i]);
    }

    // Timestamp
    {
        size_t offset = out.size();
        out.resize(out.size() + 8);
        write_le(&out[offset], timestamp);
    }

    // Network name
    write_string(out, network_name);

    return out;
}

std::optional<NodeInfo> NodeInfo::parse(std::span<const uint8_t> data, size_t& offset) {
    NodeInfo info;

    // Public key
    if (offset + crypto::KEY_SIZE > data.size()) return std::nullopt;
    std::memcpy(info.public_key.data(), &data[offset], crypto::KEY_SIZE);
    offset += crypto::KEY_SIZE;

    // Node ID
    if (offset + NODE_ID_SIZE > data.size()) return std::nullopt;
    std::memcpy(info.node_id.data(), &data[offset], NODE_ID_SIZE);
    offset += NODE_ID_SIZE;

    // VPN IPv4
    auto ipv4 = read_ip_address(data, offset);
    if (!ipv4) return std::nullopt;
    info.vpn_ipv4 = *ipv4;

    // VPN IPv6
    if (offset >= data.size()) return std::nullopt;
    uint8_t has_ipv6 = data[offset++];
    if (has_ipv6) {
        auto ipv6 = read_ip_address(data, offset);
        if (!ipv6) return std::nullopt;
        info.vpn_ipv6 = *ipv6;
    }

    // Endpoints
    if (offset >= data.size()) return std::nullopt;
    uint8_t num_endpoints = data[offset++];
    for (uint8_t i = 0; i < num_endpoints; ++i) {
        auto ep = read_socket_address(data, offset);
        if (!ep) return std::nullopt;
        info.endpoints.push_back(*ep);
    }

    // Timestamp
    if (offset + 8 > data.size()) return std::nullopt;
    info.timestamp = read_le<uint64_t>(&data[offset]);
    offset += 8;

    // Network name
    auto name = read_string(data, offset);
    if (!name) return std::nullopt;
    info.network_name = *name;

    return info;
}

// --- Utility functions ---

NodeId derive_node_id(const crypto::PublicKey& public_key) {
    auto hash = crypto::blake2s(public_key.span());
    NodeId id;
    std::memcpy(id.data(), hash.data(), NODE_ID_SIZE);
    return id;
}

NodeId xor_distance(const NodeId& a, const NodeId& b) {
    NodeId result;
    for (size_t i = 0; i < NODE_ID_SIZE; ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

bool is_closer(const NodeId& target, const NodeId& a, const NodeId& b) {
    auto dist_a = xor_distance(target, a);
    auto dist_b = xor_distance(target, b);
    return dist_a < dist_b;
}

int highest_bit(const NodeId& id) {
    for (int i = 0; i < static_cast<int>(NODE_ID_SIZE); ++i) {
        if (id[i] != 0) {
            for (int bit = 7; bit >= 0; --bit) {
                if (id[i] & (1 << bit)) {
                    return (NODE_ID_BITS - 1) - (i * 8 + (7 - bit));
                }
            }
        }
    }
    return -1;
}

bool is_mesh_message(std::span<const uint8_t> data) {
    if (data.size() < MESH_HEADER_SIZE) return false;
    return data[0] == MESH_MAGIC[0] &&
           data[1] == MESH_MAGIC[1] &&
           data[2] == MESH_MAGIC[2] &&
           data[3] == MESH_MAGIC[3];
}

// --- Build/parse mesh message ---

std::vector<uint8_t> build_mesh_message(MeshMessageType type, std::span<const uint8_t> payload) {
    std::vector<uint8_t> out(MESH_HEADER_SIZE + payload.size());
    std::memcpy(out.data(), MESH_MAGIC.data(), 4);
    out[4] = static_cast<uint8_t>(type);
    out[5] = MESH_PROTOCOL_VERSION;
    write_le(&out[6], static_cast<uint16_t>(payload.size()));
    if (!payload.empty()) {
        std::memcpy(&out[MESH_HEADER_SIZE], payload.data(), payload.size());
    }
    return out;
}

std::optional<MeshHeader> parse_mesh_header(std::span<const uint8_t> data) {
    if (!is_mesh_message(data)) return std::nullopt;

    MeshHeader header;
    header.type = static_cast<MeshMessageType>(data[4]);
    header.version = data[5];
    header.payload_length = read_le<uint16_t>(&data[6]);

    if (data.size() < MESH_HEADER_SIZE + header.payload_length) {
        return std::nullopt;
    }

    return header;
}

// --- MeshRegister ---

std::vector<uint8_t> MeshRegister::serialize() const {
    auto node_data = node_info.serialize();
    std::vector<uint8_t> payload;
    payload.reserve(node_data.size() + 2 + network_secret.size());

    payload.insert(payload.end(), node_data.begin(), node_data.end());
    write_bytes(payload, network_secret);

    return build_mesh_message(MeshMessageType::Register, payload);
}

std::optional<MeshRegister> MeshRegister::parse(std::span<const uint8_t> payload) {
    MeshRegister msg;
    size_t offset = 0;

    auto info = NodeInfo::parse(payload, offset);
    if (!info) return std::nullopt;
    msg.node_info = *info;

    auto secret = read_bytes(payload, offset);
    if (!secret) return std::nullopt;
    msg.network_secret = *secret;

    return msg;
}

// --- MeshRegisterAck ---

std::vector<uint8_t> MeshRegisterAck::serialize() const {
    std::vector<uint8_t> payload;
    payload.reserve(1 + NODE_ID_SIZE + 2 + message.size());

    payload.push_back(accepted ? 1 : 0);
    payload.insert(payload.end(), assigned_node_id.begin(), assigned_node_id.end());
    write_string(payload, message);

    return build_mesh_message(MeshMessageType::RegisterAck, payload);
}

std::optional<MeshRegisterAck> MeshRegisterAck::parse(std::span<const uint8_t> payload) {
    MeshRegisterAck msg;
    size_t offset = 0;

    if (offset + 1 + NODE_ID_SIZE > payload.size()) return std::nullopt;
    msg.accepted = payload[offset++] != 0;
    std::memcpy(msg.assigned_node_id.data(), &payload[offset], NODE_ID_SIZE);
    offset += NODE_ID_SIZE;

    auto message = read_string(payload, offset);
    if (!message) return std::nullopt;
    msg.message = *message;

    return msg;
}

// --- MeshPeerList ---

std::vector<uint8_t> MeshPeerList::serialize() const {
    std::vector<uint8_t> payload;

    uint16_t count = static_cast<uint16_t>(peers.size());
    payload.resize(2);
    write_le(payload.data(), count);

    for (const auto& peer : peers) {
        auto data = peer.serialize();
        payload.insert(payload.end(), data.begin(), data.end());
    }

    return build_mesh_message(MeshMessageType::PeerList, payload);
}

std::optional<MeshPeerList> MeshPeerList::parse(std::span<const uint8_t> payload) {
    MeshPeerList msg;

    if (payload.size() < 2) return std::nullopt;
    uint16_t count = read_le<uint16_t>(payload.data());
    size_t offset = 2;

    for (uint16_t i = 0; i < count; ++i) {
        auto info = NodeInfo::parse(payload, offset);
        if (!info) return std::nullopt;
        msg.peers.push_back(*info);
    }

    return msg;
}

// --- MeshPeerListRequest ---

std::vector<uint8_t> MeshPeerListRequest::serialize() const {
    std::vector<uint8_t> payload(8);
    write_le(payload.data(), since_timestamp);
    return build_mesh_message(MeshMessageType::PeerListRequest, payload);
}

std::optional<MeshPeerListRequest> MeshPeerListRequest::parse(std::span<const uint8_t> payload) {
    if (payload.size() < 8) return std::nullopt;
    MeshPeerListRequest msg;
    msg.since_timestamp = read_le<uint64_t>(payload.data());
    return msg;
}

// --- MeshPing ---

std::vector<uint8_t> MeshPing::serialize() const {
    std::vector<uint8_t> payload(16);
    write_le(payload.data(), nonce);
    write_le(&payload[8], timestamp);
    return build_mesh_message(MeshMessageType::MeshPing, payload);
}

std::optional<MeshPing> MeshPing::parse(std::span<const uint8_t> payload) {
    if (payload.size() < 16) return std::nullopt;
    MeshPing msg;
    msg.nonce = read_le<uint64_t>(payload.data());
    msg.timestamp = read_le<uint64_t>(&payload[8]);
    return msg;
}

// --- MeshPong ---

std::vector<uint8_t> MeshPong::serialize() const {
    std::vector<uint8_t> payload(16);
    write_le(payload.data(), nonce);
    write_le(&payload[8], timestamp);
    return build_mesh_message(MeshMessageType::MeshPong, payload);
}

std::optional<MeshPong> MeshPong::parse(std::span<const uint8_t> payload) {
    if (payload.size() < 16) return std::nullopt;
    MeshPong msg;
    msg.nonce = read_le<uint64_t>(payload.data());
    msg.timestamp = read_le<uint64_t>(&payload[8]);
    return msg;
}

// --- MeshRouteAdvertise ---

std::vector<uint8_t> MeshRouteAdvertise::serialize() const {
    std::vector<uint8_t> payload;
    uint16_t count = static_cast<uint16_t>(routes.size());
    payload.resize(2);
    write_le(payload.data(), count);

    for (const auto& route : routes) {
        write_subnet(payload, route.subnet);
        payload.push_back(route.metric);
    }

    return build_mesh_message(MeshMessageType::RouteAdvertise, payload);
}

std::optional<MeshRouteAdvertise> MeshRouteAdvertise::parse(std::span<const uint8_t> payload) {
    if (payload.size() < 2) return std::nullopt;
    MeshRouteAdvertise msg;
    uint16_t count = read_le<uint16_t>(payload.data());
    size_t offset = 2;

    for (uint16_t i = 0; i < count; ++i) {
        auto subnet = read_subnet(payload, offset);
        if (!subnet) return std::nullopt;
        if (offset >= payload.size()) return std::nullopt;
        uint8_t metric = payload[offset++];
        msg.routes.push_back({*subnet, metric});
    }

    return msg;
}

// --- MeshRouteWithdraw ---

std::vector<uint8_t> MeshRouteWithdraw::serialize() const {
    std::vector<uint8_t> payload;
    uint16_t count = static_cast<uint16_t>(routes.size());
    payload.resize(2);
    write_le(payload.data(), count);

    for (const auto& route : routes) {
        write_subnet(payload, route);
    }

    return build_mesh_message(MeshMessageType::RouteWithdraw, payload);
}

std::optional<MeshRouteWithdraw> MeshRouteWithdraw::parse(std::span<const uint8_t> payload) {
    if (payload.size() < 2) return std::nullopt;
    MeshRouteWithdraw msg;
    uint16_t count = read_le<uint16_t>(payload.data());
    size_t offset = 2;

    for (uint16_t i = 0; i < count; ++i) {
        auto subnet = read_subnet(payload, offset);
        if (!subnet) return std::nullopt;
        msg.routes.push_back(*subnet);
    }

    return msg;
}

// --- MeshFindNode ---

std::vector<uint8_t> MeshFindNode::serialize() const {
    std::vector<uint8_t> payload(NODE_ID_SIZE * 2);
    std::memcpy(payload.data(), target.data(), NODE_ID_SIZE);
    std::memcpy(&payload[NODE_ID_SIZE], sender_id.data(), NODE_ID_SIZE);
    return build_mesh_message(MeshMessageType::FindNode, payload);
}

std::optional<MeshFindNode> MeshFindNode::parse(std::span<const uint8_t> payload) {
    if (payload.size() < NODE_ID_SIZE * 2) return std::nullopt;
    MeshFindNode msg;
    std::memcpy(msg.target.data(), payload.data(), NODE_ID_SIZE);
    std::memcpy(msg.sender_id.data(), &payload[NODE_ID_SIZE], NODE_ID_SIZE);
    return msg;
}

// --- MeshFindNodeResponse ---

std::vector<uint8_t> MeshFindNodeResponse::serialize() const {
    std::vector<uint8_t> payload;
    payload.reserve(NODE_ID_SIZE + 2 + 256);

    payload.insert(payload.end(), sender_id.begin(), sender_id.end());

    uint16_t count = static_cast<uint16_t>(closest_nodes.size());
    size_t offset = payload.size();
    payload.resize(payload.size() + 2);
    write_le(&payload[offset], count);

    for (const auto& node : closest_nodes) {
        auto data = node.serialize();
        payload.insert(payload.end(), data.begin(), data.end());
    }

    return build_mesh_message(MeshMessageType::FindNodeResponse, payload);
}

std::optional<MeshFindNodeResponse> MeshFindNodeResponse::parse(std::span<const uint8_t> payload) {
    MeshFindNodeResponse msg;
    size_t offset = 0;

    if (offset + NODE_ID_SIZE > payload.size()) return std::nullopt;
    std::memcpy(msg.sender_id.data(), &payload[offset], NODE_ID_SIZE);
    offset += NODE_ID_SIZE;

    if (offset + 2 > payload.size()) return std::nullopt;
    uint16_t count = read_le<uint16_t>(&payload[offset]);
    offset += 2;

    for (uint16_t i = 0; i < count; ++i) {
        auto info = NodeInfo::parse(payload, offset);
        if (!info) return std::nullopt;
        msg.closest_nodes.push_back(*info);
    }

    return msg;
}

// --- MeshStore ---

std::vector<uint8_t> MeshStore::serialize() const {
    std::vector<uint8_t> payload;
    payload.reserve(NODE_ID_SIZE + 4 + key.size() + value.size() + 8);

    payload.insert(payload.end(), sender_id.begin(), sender_id.end());
    write_bytes(payload, key);
    write_bytes(payload, value);

    size_t offset = payload.size();
    payload.resize(payload.size() + 4);
    write_le(&payload[offset], ttl_seconds);

    return build_mesh_message(MeshMessageType::Store, payload);
}

std::optional<MeshStore> MeshStore::parse(std::span<const uint8_t> payload) {
    MeshStore msg;
    size_t offset = 0;

    if (offset + NODE_ID_SIZE > payload.size()) return std::nullopt;
    std::memcpy(msg.sender_id.data(), &payload[offset], NODE_ID_SIZE);
    offset += NODE_ID_SIZE;

    auto key = read_bytes(payload, offset);
    if (!key) return std::nullopt;
    msg.key = *key;

    auto value = read_bytes(payload, offset);
    if (!value) return std::nullopt;
    msg.value = *value;

    if (offset + 4 > payload.size()) return std::nullopt;
    msg.ttl_seconds = read_le<uint32_t>(&payload[offset]);

    return msg;
}

// --- MeshFindValue ---

std::vector<uint8_t> MeshFindValue::serialize() const {
    std::vector<uint8_t> payload;
    payload.reserve(NODE_ID_SIZE + 2 + key.size());

    payload.insert(payload.end(), sender_id.begin(), sender_id.end());
    write_bytes(payload, key);

    return build_mesh_message(MeshMessageType::FindValue, payload);
}

std::optional<MeshFindValue> MeshFindValue::parse(std::span<const uint8_t> payload) {
    MeshFindValue msg;
    size_t offset = 0;

    if (offset + NODE_ID_SIZE > payload.size()) return std::nullopt;
    std::memcpy(msg.sender_id.data(), &payload[offset], NODE_ID_SIZE);
    offset += NODE_ID_SIZE;

    auto key = read_bytes(payload, offset);
    if (!key) return std::nullopt;
    msg.key = *key;

    return msg;
}

// --- MeshFindValueResponse ---

std::vector<uint8_t> MeshFindValueResponse::serialize() const {
    std::vector<uint8_t> payload;
    payload.reserve(NODE_ID_SIZE + 1 + 256);

    payload.insert(payload.end(), sender_id.begin(), sender_id.end());
    payload.push_back(found ? 1 : 0);

    if (found) {
        write_bytes(payload, value);
    } else {
        uint16_t count = static_cast<uint16_t>(closest_nodes.size());
        size_t offset = payload.size();
        payload.resize(payload.size() + 2);
        write_le(&payload[offset], count);

        for (const auto& node : closest_nodes) {
            auto data = node.serialize();
            payload.insert(payload.end(), data.begin(), data.end());
        }
    }

    return build_mesh_message(MeshMessageType::FindValueResponse, payload);
}

std::optional<MeshFindValueResponse> MeshFindValueResponse::parse(std::span<const uint8_t> payload) {
    MeshFindValueResponse msg;
    size_t offset = 0;

    if (offset + NODE_ID_SIZE + 1 > payload.size()) return std::nullopt;
    std::memcpy(msg.sender_id.data(), &payload[offset], NODE_ID_SIZE);
    offset += NODE_ID_SIZE;
    msg.found = payload[offset++] != 0;

    if (msg.found) {
        auto value = read_bytes(payload, offset);
        if (!value) return std::nullopt;
        msg.value = *value;
    } else {
        if (offset + 2 > payload.size()) return std::nullopt;
        uint16_t count = read_le<uint16_t>(&payload[offset]);
        offset += 2;

        for (uint16_t i = 0; i < count; ++i) {
            auto info = NodeInfo::parse(payload, offset);
            if (!info) return std::nullopt;
            msg.closest_nodes.push_back(*info);
        }
    }

    return msg;
}

// --- MeshPunchRequest ---

std::vector<uint8_t> MeshPunchRequest::serialize() const {
    std::vector<uint8_t> payload(NODE_ID_SIZE + crypto::KEY_SIZE);
    std::memcpy(payload.data(), target_node_id.data(), NODE_ID_SIZE);
    std::memcpy(&payload[NODE_ID_SIZE], target_public_key.data(), crypto::KEY_SIZE);
    return build_mesh_message(MeshMessageType::PunchRequest, payload);
}

std::optional<MeshPunchRequest> MeshPunchRequest::parse(std::span<const uint8_t> payload) {
    if (payload.size() < NODE_ID_SIZE + crypto::KEY_SIZE) return std::nullopt;
    MeshPunchRequest msg;
    std::memcpy(msg.target_node_id.data(), payload.data(), NODE_ID_SIZE);
    std::memcpy(msg.target_public_key.data(), &payload[NODE_ID_SIZE], crypto::KEY_SIZE);
    return msg;
}

// --- MeshPunchNotify ---

std::vector<uint8_t> MeshPunchNotify::serialize() const {
    auto node_data = requester_info.serialize();
    std::vector<uint8_t> payload;
    payload.reserve(node_data.size() + 8);

    payload.insert(payload.end(), node_data.begin(), node_data.end());

    size_t offset = payload.size();
    payload.resize(payload.size() + 8);
    write_le(&payload[offset], punch_nonce);

    return build_mesh_message(MeshMessageType::PunchNotify, payload);
}

std::optional<MeshPunchNotify> MeshPunchNotify::parse(std::span<const uint8_t> payload) {
    MeshPunchNotify msg;
    size_t offset = 0;

    auto info = NodeInfo::parse(payload, offset);
    if (!info) return std::nullopt;
    msg.requester_info = *info;

    if (offset + 8 > payload.size()) return std::nullopt;
    msg.punch_nonce = read_le<uint64_t>(&payload[offset]);

    return msg;
}

} // namespace vpn::mesh
