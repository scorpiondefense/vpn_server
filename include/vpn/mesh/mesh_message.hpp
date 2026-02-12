#pragma once

#include "vpn/crypto/types.hpp"
#include "vpn/net/address.hpp"
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace vpn::mesh {

// Magic prefix for mesh control messages inside WireGuard transport data
inline constexpr std::array<uint8_t, 4> MESH_MAGIC = {'M', 'E', 'S', 'H'};

// Mesh message header size: 4B magic + 1B type + 1B version + 2B payload_len
inline constexpr size_t MESH_HEADER_SIZE = 8;

// Current protocol version
inline constexpr uint8_t MESH_PROTOCOL_VERSION = 1;

// Node ID size (160 bits = 20 bytes, SHA-256 truncated)
inline constexpr size_t NODE_ID_SIZE = 20;

// Kademlia parameters
inline constexpr size_t K_BUCKET_SIZE = 20;
inline constexpr size_t ALPHA = 3;
inline constexpr size_t NODE_ID_BITS = NODE_ID_SIZE * 8;  // 160 bits

using NodeId = std::array<uint8_t, NODE_ID_SIZE>;

// Mesh message types
enum class MeshMessageType : uint8_t {
    Register          = 0x01,
    RegisterAck       = 0x02,
    PeerList          = 0x03,
    PeerListRequest   = 0x04,
    MeshPing          = 0x10,
    MeshPong          = 0x11,
    RouteAdvertise    = 0x20,
    RouteWithdraw     = 0x21,
    FindNode          = 0x30,
    FindNodeResponse  = 0x31,
    Store             = 0x32,
    FindValue         = 0x33,
    FindValueResponse = 0x34,
    PunchRequest      = 0x40,
    PunchNotify       = 0x41,
};

// Node information shared across the mesh
struct NodeInfo {
    crypto::PublicKey public_key;
    NodeId node_id;
    net::IpAddress vpn_ipv4;
    std::optional<net::IpAddress> vpn_ipv6;
    std::vector<net::SocketAddress> endpoints;
    uint64_t timestamp;
    std::string network_name;

    std::vector<uint8_t> serialize() const;
    static std::optional<NodeInfo> parse(std::span<const uint8_t> data, size_t& offset);
};

// Derive node ID from WireGuard public key (SHA-256 truncated to 160 bits)
NodeId derive_node_id(const crypto::PublicKey& public_key);

// XOR distance between two node IDs
NodeId xor_distance(const NodeId& a, const NodeId& b);

// Compare XOR distances: is a closer to target than b?
bool is_closer(const NodeId& target, const NodeId& a, const NodeId& b);

// Find the index of the highest set bit in a node ID (0-159, or -1 if zero)
int highest_bit(const NodeId& id);

// Check if data starts with mesh magic
bool is_mesh_message(std::span<const uint8_t> data);

// --- Mesh message structures ---

struct MeshRegister {
    NodeInfo node_info;
    std::vector<uint8_t> network_secret;  // HMAC proof of network membership

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshRegister> parse(std::span<const uint8_t> payload);
};

struct MeshRegisterAck {
    bool accepted;
    NodeId assigned_node_id;
    std::string message;

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshRegisterAck> parse(std::span<const uint8_t> payload);
};

struct MeshPeerList {
    std::vector<NodeInfo> peers;

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshPeerList> parse(std::span<const uint8_t> payload);
};

struct MeshPeerListRequest {
    uint64_t since_timestamp;  // Only peers updated after this time

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshPeerListRequest> parse(std::span<const uint8_t> payload);
};

struct MeshPing {
    uint64_t nonce;
    uint64_t timestamp;

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshPing> parse(std::span<const uint8_t> payload);
};

struct MeshPong {
    uint64_t nonce;      // Echo back the nonce from ping
    uint64_t timestamp;  // Responder's timestamp

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshPong> parse(std::span<const uint8_t> payload);
};

struct RouteInfo {
    net::Subnet subnet;
    uint8_t metric;
};

struct MeshRouteAdvertise {
    std::vector<RouteInfo> routes;

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshRouteAdvertise> parse(std::span<const uint8_t> payload);
};

struct MeshRouteWithdraw {
    std::vector<net::Subnet> routes;

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshRouteWithdraw> parse(std::span<const uint8_t> payload);
};

// Kademlia messages
struct MeshFindNode {
    NodeId target;
    NodeId sender_id;

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshFindNode> parse(std::span<const uint8_t> payload);
};

struct MeshFindNodeResponse {
    NodeId sender_id;
    std::vector<NodeInfo> closest_nodes;

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshFindNodeResponse> parse(std::span<const uint8_t> payload);
};

struct MeshStore {
    NodeId sender_id;
    std::vector<uint8_t> key;
    std::vector<uint8_t> value;
    uint32_t ttl_seconds;

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshStore> parse(std::span<const uint8_t> payload);
};

struct MeshFindValue {
    NodeId sender_id;
    std::vector<uint8_t> key;

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshFindValue> parse(std::span<const uint8_t> payload);
};

struct MeshFindValueResponse {
    NodeId sender_id;
    bool found;
    std::vector<uint8_t> value;          // If found
    std::vector<NodeInfo> closest_nodes;  // If not found

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshFindValueResponse> parse(std::span<const uint8_t> payload);
};

// NAT traversal messages
struct MeshPunchRequest {
    NodeId target_node_id;
    crypto::PublicKey target_public_key;

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshPunchRequest> parse(std::span<const uint8_t> payload);
};

struct MeshPunchNotify {
    NodeInfo requester_info;
    uint64_t punch_nonce;

    std::vector<uint8_t> serialize() const;
    static std::optional<MeshPunchNotify> parse(std::span<const uint8_t> payload);
};

// Build a complete mesh message with header
std::vector<uint8_t> build_mesh_message(MeshMessageType type, std::span<const uint8_t> payload);

// Parse mesh message header, returns type and payload span
struct MeshHeader {
    MeshMessageType type;
    uint8_t version;
    uint16_t payload_length;
};

std::optional<MeshHeader> parse_mesh_header(std::span<const uint8_t> data);

} // namespace vpn::mesh
