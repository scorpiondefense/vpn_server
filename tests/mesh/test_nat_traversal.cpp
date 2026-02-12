#include <catch2/catch_test_macros.hpp>
#include "vpn/mesh/nat_traversal.hpp"
#include "vpn/crypto/curve25519.hpp"

using namespace vpn::mesh;
using namespace vpn::net;
using namespace vpn::crypto;

TEST_CASE("NatDiscovery classification", "[mesh][nat]") {
    NatDiscovery discovery;

    SECTION("Unknown when no data") {
        auto result = discovery.result();
        REQUIRE(result.type == NatType::Unknown);
    }

    SECTION("Open internet when local matches reflexive") {
        auto addr = *SocketAddress::parse("1.2.3.4:51820");
        discovery.set_local_address(addr);
        discovery.set_reflexive_address(addr);

        auto result = discovery.result();
        REQUIRE(result.type == NatType::OpenInternet);
    }

    SECTION("Restricted cone when IPs differ") {
        discovery.set_local_address(*SocketAddress::parse("192.168.1.100:51820"));
        discovery.set_reflexive_address(*SocketAddress::parse("1.2.3.4:51820"));

        auto result = discovery.result();
        REQUIRE(result.type == NatType::RestrictedCone);
    }

    SECTION("Port restricted when same IP different port") {
        discovery.set_local_address(*SocketAddress::parse("1.2.3.4:51820"));
        discovery.set_reflexive_address(*SocketAddress::parse("1.2.3.4:12345"));

        auto result = discovery.result();
        REQUIRE(result.type == NatType::PortRestricted);
    }
}

TEST_CASE("NatDiscovery endpoint list", "[mesh][nat]") {
    NatDiscovery discovery;

    SECTION("Empty when no data") {
        auto endpoints = discovery.build_endpoint_list();
        REQUIRE(endpoints.empty());
    }

    SECTION("Single endpoint when local == reflexive") {
        auto addr = *SocketAddress::parse("1.2.3.4:51820");
        discovery.set_local_address(addr);
        discovery.set_reflexive_address(addr);

        auto endpoints = discovery.build_endpoint_list();
        REQUIRE(endpoints.size() == 1);
    }

    SECTION("Two endpoints when different") {
        discovery.set_local_address(*SocketAddress::parse("192.168.1.100:51820"));
        discovery.set_reflexive_address(*SocketAddress::parse("1.2.3.4:51820"));

        auto endpoints = discovery.build_endpoint_list();
        REQUIRE(endpoints.size() == 2);
    }
}

TEST_CASE("HolePuncher basic operations", "[mesh][nat]") {
    int send_count = 0;
    HolePuncher puncher([&](const std::vector<uint8_t>& data,
                             const SocketAddress& to) -> bool {
        send_count++;
        return true;
    });

    REQUIRE(puncher.active_attempts() == 0);

    // Create a target node
    auto kp = Curve25519KeyPair::generate();
    NodeInfo target;
    target.public_key = kp.public_key();
    target.node_id = derive_node_id(kp.public_key());
    target.vpn_ipv4 = IpAddress(IPv4Address(10, 0, 0, 2));
    target.endpoints.push_back(*SocketAddress::parse("1.2.3.4:51820"));
    target.endpoints.push_back(*SocketAddress::parse("5.6.7.8:51820"));

    puncher.initiate(target, 12345);
    REQUIRE(puncher.active_attempts() == 1);

    // Tick should send probes
    puncher.tick();
    REQUIRE(send_count == 2);  // One probe per endpoint
}

TEST_CASE("RelayManager basic operations", "[mesh][nat]") {
    RelayManager relay;

    auto kp1 = Curve25519KeyPair::generate();
    auto kp2 = Curve25519KeyPair::generate();

    NodeId target = derive_node_id(kp1.public_key());

    REQUIRE_FALSE(relay.has_relay(target));
    REQUIRE_FALSE(relay.find_relay(target).has_value());

    // Add relay
    relay.add_relay(target, kp2.public_key());
    REQUIRE(relay.has_relay(target));

    auto found = relay.find_relay(target);
    REQUIRE(found.has_value());
    REQUIRE(*found == kp2.public_key());

    // All routes
    auto routes = relay.all_routes();
    REQUIRE(routes.size() == 1);

    // Remove
    relay.remove_relay(target);
    REQUIRE_FALSE(relay.has_relay(target));
}
