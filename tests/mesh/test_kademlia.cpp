#include <catch2/catch_test_macros.hpp>
#include "vpn/mesh/kademlia.hpp"
#include "vpn/crypto/curve25519.hpp"
#include <thread>

using namespace vpn::mesh;
using namespace vpn::crypto;

namespace {

NodeInfo make_node_info(const Curve25519KeyPair& kp) {
    NodeInfo info;
    info.public_key = kp.public_key();
    info.node_id = derive_node_id(kp.public_key());
    info.vpn_ipv4 = vpn::net::IpAddress(vpn::net::IPv4Address(10, 0, 0, 1));
    info.timestamp = 1000;
    info.network_name = "test";
    return info;
}

} // anonymous namespace

TEST_CASE("KBucket basic operations", "[mesh][kademlia]") {
    KBucket bucket;

    REQUIRE(bucket.is_empty());
    REQUIRE_FALSE(bucket.is_full());

    // Add a node
    auto kp = Curve25519KeyPair::generate();
    KBucketEntry entry;
    entry.node_id = derive_node_id(kp.public_key());
    entry.info = make_node_info(kp);
    entry.last_seen = std::chrono::steady_clock::now();

    REQUIRE(bucket.add_or_update(entry));
    REQUIRE(bucket.size() == 1);
    REQUIRE_FALSE(bucket.is_empty());

    // Find the node
    auto found = bucket.find(entry.node_id);
    REQUIRE(found != nullptr);
    REQUIRE(found->node_id == entry.node_id);
}

TEST_CASE("KBucket LRU ordering", "[mesh][kademlia]") {
    KBucket bucket;

    // Add three nodes
    std::vector<NodeId> ids;
    for (int i = 0; i < 3; ++i) {
        auto kp = Curve25519KeyPair::generate();
        KBucketEntry entry;
        entry.node_id = derive_node_id(kp.public_key());
        entry.info = make_node_info(kp);
        entry.last_seen = std::chrono::steady_clock::now();
        bucket.add_or_update(entry);
        ids.push_back(entry.node_id);
    }

    REQUIRE(bucket.size() == 3);

    // Head should be the first added (least recently seen)
    REQUIRE(bucket.head()->node_id == ids[0]);

    // Re-add the first node — it should move to tail
    auto kp_refresh = Curve25519KeyPair::generate();
    KBucketEntry refresh_entry;
    refresh_entry.node_id = ids[0];
    refresh_entry.info = make_node_info(kp_refresh);
    refresh_entry.info.node_id = ids[0];
    refresh_entry.last_seen = std::chrono::steady_clock::now();
    bucket.add_or_update(refresh_entry);

    // Now head should be the second node
    REQUIRE(bucket.head()->node_id == ids[1]);
}

TEST_CASE("KBucket capacity", "[mesh][kademlia]") {
    KBucket bucket;

    // Fill the bucket
    for (size_t i = 0; i < K_BUCKET_SIZE; ++i) {
        auto kp = Curve25519KeyPair::generate();
        KBucketEntry entry;
        entry.node_id = derive_node_id(kp.public_key());
        entry.info = make_node_info(kp);
        entry.last_seen = std::chrono::steady_clock::now();
        REQUIRE(bucket.add_or_update(entry));
    }

    REQUIRE(bucket.is_full());

    // Adding one more should fail
    auto kp_extra = Curve25519KeyPair::generate();
    KBucketEntry extra;
    extra.node_id = derive_node_id(kp_extra.public_key());
    extra.info = make_node_info(kp_extra);
    extra.last_seen = std::chrono::steady_clock::now();
    REQUIRE_FALSE(bucket.add_or_update(extra));
}

TEST_CASE("RoutingTable basic operations", "[mesh][kademlia]") {
    auto local_kp = Curve25519KeyPair::generate();
    auto local_id = derive_node_id(local_kp.public_key());
    RoutingTable table(local_id);

    REQUIRE(table.node_count() == 0);

    // Add some nodes
    std::vector<NodeInfo> nodes;
    for (int i = 0; i < 10; ++i) {
        auto kp = Curve25519KeyPair::generate();
        auto info = make_node_info(kp);
        nodes.push_back(info);
        REQUIRE(table.add_or_update(info));
    }

    REQUIRE(table.node_count() == 10);

    // Find closest should return nodes
    auto closest = table.find_closest(nodes[0].node_id, 5);
    REQUIRE(closest.size() <= 5);
    REQUIRE(!closest.empty());
}

TEST_CASE("RoutingTable does not add self", "[mesh][kademlia]") {
    auto local_kp = Curve25519KeyPair::generate();
    auto local_id = derive_node_id(local_kp.public_key());
    RoutingTable table(local_id);

    NodeInfo self_info;
    self_info.public_key = local_kp.public_key();
    self_info.node_id = local_id;
    self_info.vpn_ipv4 = vpn::net::IpAddress(vpn::net::IPv4Address(10, 0, 0, 1));

    REQUIRE_FALSE(table.add_or_update(self_info));
    REQUIRE(table.node_count() == 0);
}

TEST_CASE("RoutingTable find_closest ordering", "[mesh][kademlia]") {
    auto local_kp = Curve25519KeyPair::generate();
    auto local_id = derive_node_id(local_kp.public_key());
    RoutingTable table(local_id);

    // Add many nodes
    for (int i = 0; i < 50; ++i) {
        auto kp = Curve25519KeyPair::generate();
        table.add_or_update(make_node_info(kp));
    }

    // Pick a random target
    auto target_kp = Curve25519KeyPair::generate();
    auto target_id = derive_node_id(target_kp.public_key());

    auto closest = table.find_closest(target_id, 10);
    REQUIRE(!closest.empty());

    // Verify ordering: each node should be closer to target than the next
    for (size_t i = 1; i < closest.size(); ++i) {
        auto dist_prev = xor_distance(target_id, closest[i-1].node_id);
        auto dist_curr = xor_distance(target_id, closest[i].node_id);
        REQUIRE(dist_prev <= dist_curr);
    }
}

TEST_CASE("RoutingTable remove", "[mesh][kademlia]") {
    auto local_kp = Curve25519KeyPair::generate();
    auto local_id = derive_node_id(local_kp.public_key());
    RoutingTable table(local_id);

    auto kp = Curve25519KeyPair::generate();
    auto info = make_node_info(kp);
    table.add_or_update(info);
    REQUIRE(table.node_count() == 1);

    table.remove(info.node_id);
    REQUIRE(table.node_count() == 0);
}

TEST_CASE("DhtStore basic operations", "[mesh][kademlia]") {
    DhtStore store;

    std::vector<uint8_t> key = {1, 2, 3};
    std::vector<uint8_t> value = {10, 20, 30};
    NodeId publisher{};

    // Store and retrieve
    store.store(key, value, publisher, 3600);
    REQUIRE(store.size() == 1);

    auto found = store.find(key);
    REQUIRE(found.has_value());
    REQUIRE(*found == value);

    // Non-existent key
    std::vector<uint8_t> missing_key = {4, 5, 6};
    REQUIRE_FALSE(store.find(missing_key).has_value());
}

TEST_CASE("DhtStore TTL expiry", "[mesh][kademlia]") {
    DhtStore store;

    std::vector<uint8_t> key = {1, 2, 3};
    std::vector<uint8_t> value = {10, 20, 30};
    NodeId publisher{};

    // Store with 0-second TTL (should expire immediately)
    store.store(key, value, publisher, 0);

    // Wait a tiny bit
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Should not be found
    REQUIRE_FALSE(store.find(key).has_value());
}

TEST_CASE("IterativeLookup basic convergence", "[mesh][kademlia]") {
    auto target_kp = Curve25519KeyPair::generate();
    auto target_id = derive_node_id(target_kp.public_key());

    // Create some initial nodes
    std::vector<NodeInfo> initial_nodes;
    for (int i = 0; i < 5; ++i) {
        auto kp = Curve25519KeyPair::generate();
        initial_nodes.push_back(make_node_info(kp));
    }

    IterativeLookup lookup(target_id, initial_nodes, K_BUCKET_SIZE, ALPHA);
    REQUIRE(lookup.state() == IterativeLookup::State::Running);

    // Get first batch to query
    auto batch = lookup.next_to_query();
    REQUIRE(batch.size() <= ALPHA);

    // Simulate responses with no new nodes (converges immediately)
    for (const auto& node : batch) {
        lookup.process_response(node.node_id, {});
    }

    // Should converge since no new nodes returned
    // Get any remaining
    auto remaining = lookup.next_to_query();
    for (const auto& node : remaining) {
        lookup.process_response(node.node_id, {});
    }

    // Eventually should converge
    remaining = lookup.next_to_query();
    if (remaining.empty()) {
        REQUIRE(lookup.state() == IterativeLookup::State::Converged);
    }
}

TEST_CASE("IterativeLookup handles failures", "[mesh][kademlia]") {
    auto target_kp = Curve25519KeyPair::generate();
    auto target_id = derive_node_id(target_kp.public_key());

    std::vector<NodeInfo> initial_nodes;
    for (int i = 0; i < 3; ++i) {
        auto kp = Curve25519KeyPair::generate();
        initial_nodes.push_back(make_node_info(kp));
    }

    IterativeLookup lookup(target_id, initial_nodes);

    auto batch = lookup.next_to_query();

    // Mark all as failed
    for (const auto& node : batch) {
        lookup.mark_failed(node.node_id);
    }

    // Should still have some unqueried nodes or converge
    auto results = lookup.closest_results();
    REQUIRE(!results.empty());
}

TEST_CASE("Random ID in bucket", "[mesh][kademlia]") {
    auto local_kp = Curve25519KeyPair::generate();
    auto local_id = derive_node_id(local_kp.public_key());

    for (int bucket = 0; bucket < 10; ++bucket) {
        auto random_id = RoutingTable::random_id_in_bucket(local_id, bucket);

        // The XOR distance should have its highest bit at position bucket
        auto dist = xor_distance(local_id, random_id);
        int hb = highest_bit(dist);

        // The highest bit should be exactly at the bucket position
        REQUIRE(hb == bucket);
    }
}
