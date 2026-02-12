#include <catch2/catch_test_macros.hpp>
#include "vpn/mesh/mesh_message.hpp"
#include "vpn/crypto/curve25519.hpp"
#include <cstring>

using namespace vpn::mesh;
using namespace vpn::crypto;
using namespace vpn::net;

TEST_CASE("NodeId derivation from public key", "[mesh][message]") {
    auto kp1 = Curve25519KeyPair::generate();
    auto kp2 = Curve25519KeyPair::generate();

    auto id1 = derive_node_id(kp1.public_key());
    auto id2 = derive_node_id(kp2.public_key());

    // IDs should be deterministic
    REQUIRE(derive_node_id(kp1.public_key()) == id1);

    // Different keys should produce different IDs
    REQUIRE(id1 != id2);

    // IDs should be 20 bytes
    REQUIRE(id1.size() == NODE_ID_SIZE);
}

TEST_CASE("XOR distance properties", "[mesh][message]") {
    auto kp1 = Curve25519KeyPair::generate();
    auto kp2 = Curve25519KeyPair::generate();
    auto kp3 = Curve25519KeyPair::generate();

    auto id1 = derive_node_id(kp1.public_key());
    auto id2 = derive_node_id(kp2.public_key());
    auto id3 = derive_node_id(kp3.public_key());

    // Distance to self is zero
    auto self_dist = xor_distance(id1, id1);
    NodeId zero{};
    REQUIRE(self_dist == zero);

    // Distance is symmetric
    REQUIRE(xor_distance(id1, id2) == xor_distance(id2, id1));

    // is_closer should be consistent
    if (is_closer(id1, id2, id3)) {
        REQUIRE(!is_closer(id1, id3, id2));
    }
}

TEST_CASE("highest_bit function", "[mesh][message]") {
    NodeId zero{};
    REQUIRE(highest_bit(zero) == -1);

    NodeId one{};
    one[NODE_ID_SIZE - 1] = 1;
    REQUIRE(highest_bit(one) == 0);

    NodeId high{};
    high[0] = 0x80;
    REQUIRE(highest_bit(high) == NODE_ID_BITS - 1);

    NodeId mid{};
    mid[10] = 0x40;  // bit 6 of byte 10
    // Bit position: (NODE_ID_BITS - 1) - (10 * 8 + (7 - 6)) = 159 - 81 = 78
    REQUIRE(highest_bit(mid) == 78);
}

TEST_CASE("Mesh message header", "[mesh][message]") {
    std::vector<uint8_t> payload = {1, 2, 3, 4, 5};
    auto msg = build_mesh_message(MeshMessageType::MeshPing, payload);

    REQUIRE(msg.size() == MESH_HEADER_SIZE + payload.size());
    REQUIRE(is_mesh_message(msg));

    auto header = parse_mesh_header(msg);
    REQUIRE(header.has_value());
    REQUIRE(header->type == MeshMessageType::MeshPing);
    REQUIRE(header->version == MESH_PROTOCOL_VERSION);
    REQUIRE(header->payload_length == payload.size());
}

TEST_CASE("is_mesh_message rejects non-mesh data", "[mesh][message]") {
    std::vector<uint8_t> empty;
    REQUIRE_FALSE(is_mesh_message(empty));

    std::vector<uint8_t> short_data = {1, 2, 3};
    REQUIRE_FALSE(is_mesh_message(short_data));

    std::vector<uint8_t> wrong_magic = {'N', 'O', 'P', 'E', 0, 1, 0, 0};
    REQUIRE_FALSE(is_mesh_message(wrong_magic));
}

TEST_CASE("MeshPing serialization round-trip", "[mesh][message]") {
    MeshPing original;
    original.nonce = 0x123456789ABCDEF0ULL;
    original.timestamp = 1234567890;

    auto serialized = original.serialize();
    auto header = parse_mesh_header(serialized);
    REQUIRE(header.has_value());
    REQUIRE(header->type == MeshMessageType::MeshPing);

    auto payload = std::span<const uint8_t>(serialized).subspan(MESH_HEADER_SIZE, header->payload_length);
    auto parsed = MeshPing::parse(payload);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->nonce == original.nonce);
    REQUIRE(parsed->timestamp == original.timestamp);
}

TEST_CASE("MeshPong serialization round-trip", "[mesh][message]") {
    MeshPong original;
    original.nonce = 42;
    original.timestamp = 9876543210;

    auto serialized = original.serialize();
    auto header = parse_mesh_header(serialized);
    REQUIRE(header.has_value());

    auto payload = std::span<const uint8_t>(serialized).subspan(MESH_HEADER_SIZE, header->payload_length);
    auto parsed = MeshPong::parse(payload);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->nonce == original.nonce);
    REQUIRE(parsed->timestamp == original.timestamp);
}

TEST_CASE("MeshPeerListRequest serialization round-trip", "[mesh][message]") {
    MeshPeerListRequest original;
    original.since_timestamp = 1000000;

    auto serialized = original.serialize();
    auto header = parse_mesh_header(serialized);
    REQUIRE(header.has_value());

    auto payload = std::span<const uint8_t>(serialized).subspan(MESH_HEADER_SIZE, header->payload_length);
    auto parsed = MeshPeerListRequest::parse(payload);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->since_timestamp == original.since_timestamp);
}

TEST_CASE("NodeInfo serialization round-trip", "[mesh][message]") {
    auto kp = Curve25519KeyPair::generate();

    NodeInfo original;
    original.public_key = kp.public_key();
    original.node_id = derive_node_id(kp.public_key());
    original.vpn_ipv4 = IpAddress(IPv4Address(10, 100, 0, 1));
    original.vpn_ipv6 = IpAddress(*IPv6Address::parse("fd00:mesh::1"));
    original.endpoints.push_back(*SocketAddress::parse("192.168.1.100:51820"));
    original.endpoints.push_back(*SocketAddress::parse("1.2.3.4:51820"));
    original.timestamp = 1234567890;
    original.network_name = "test-network";

    auto serialized = original.serialize();

    size_t offset = 0;
    auto parsed = NodeInfo::parse(serialized, offset);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->public_key == original.public_key);
    REQUIRE(parsed->node_id == original.node_id);
    REQUIRE(parsed->vpn_ipv4.to_string() == original.vpn_ipv4.to_string());
    REQUIRE(parsed->vpn_ipv6.has_value());
    REQUIRE(parsed->endpoints.size() == 2);
    REQUIRE(parsed->timestamp == original.timestamp);
    REQUIRE(parsed->network_name == original.network_name);
}

TEST_CASE("MeshFindNode serialization round-trip", "[mesh][message]") {
    auto kp = Curve25519KeyPair::generate();

    MeshFindNode original;
    original.target = derive_node_id(kp.public_key());
    original.sender_id = derive_node_id(Curve25519KeyPair::generate().public_key());

    auto serialized = original.serialize();
    auto header = parse_mesh_header(serialized);
    REQUIRE(header.has_value());
    REQUIRE(header->type == MeshMessageType::FindNode);

    auto payload = std::span<const uint8_t>(serialized).subspan(MESH_HEADER_SIZE, header->payload_length);
    auto parsed = MeshFindNode::parse(payload);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->target == original.target);
    REQUIRE(parsed->sender_id == original.sender_id);
}

TEST_CASE("MeshRegisterAck serialization round-trip", "[mesh][message]") {
    MeshRegisterAck original;
    original.accepted = true;
    original.assigned_node_id = derive_node_id(Curve25519KeyPair::generate().public_key());
    original.message = "Registration successful";

    auto serialized = original.serialize();
    auto header = parse_mesh_header(serialized);
    REQUIRE(header.has_value());

    auto payload = std::span<const uint8_t>(serialized).subspan(MESH_HEADER_SIZE, header->payload_length);
    auto parsed = MeshRegisterAck::parse(payload);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->accepted == original.accepted);
    REQUIRE(parsed->assigned_node_id == original.assigned_node_id);
    REQUIRE(parsed->message == original.message);
}

TEST_CASE("MeshStore serialization round-trip", "[mesh][message]") {
    MeshStore original;
    original.sender_id = derive_node_id(Curve25519KeyPair::generate().public_key());
    original.key = {1, 2, 3, 4, 5};
    original.value = {10, 20, 30, 40, 50, 60};
    original.ttl_seconds = 3600;

    auto serialized = original.serialize();
    auto header = parse_mesh_header(serialized);
    REQUIRE(header.has_value());

    auto payload = std::span<const uint8_t>(serialized).subspan(MESH_HEADER_SIZE, header->payload_length);
    auto parsed = MeshStore::parse(payload);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->sender_id == original.sender_id);
    REQUIRE(parsed->key == original.key);
    REQUIRE(parsed->value == original.value);
    REQUIRE(parsed->ttl_seconds == original.ttl_seconds);
}

TEST_CASE("MeshPunchRequest serialization round-trip", "[mesh][message]") {
    auto kp = Curve25519KeyPair::generate();

    MeshPunchRequest original;
    original.target_node_id = derive_node_id(kp.public_key());
    original.target_public_key = kp.public_key();

    auto serialized = original.serialize();
    auto header = parse_mesh_header(serialized);
    REQUIRE(header.has_value());

    auto payload = std::span<const uint8_t>(serialized).subspan(MESH_HEADER_SIZE, header->payload_length);
    auto parsed = MeshPunchRequest::parse(payload);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->target_node_id == original.target_node_id);
    REQUIRE(parsed->target_public_key == original.target_public_key);
}
