#include <catch2/catch_test_macros.hpp>
#include "vpn/net/udp_socket.hpp"
#include "vpn/net/address.hpp"
#include <thread>
#include <chrono>

using namespace vpn::net;

TEST_CASE("IPv4Address parsing and operations", "[net][address]") {
    SECTION("Parse valid IPv4") {
        auto addr = IPv4Address::parse("192.168.1.1");
        REQUIRE(addr.has_value());
        REQUIRE(addr->to_string() == "192.168.1.1");
    }

    SECTION("Parse invalid IPv4") {
        REQUIRE_FALSE(IPv4Address::parse("256.1.1.1").has_value());
        REQUIRE_FALSE(IPv4Address::parse("not an ip").has_value());
        REQUIRE_FALSE(IPv4Address::parse("").has_value());
    }

    SECTION("Construct from components") {
        IPv4Address addr(10, 0, 0, 1);
        REQUIRE(addr.to_string() == "10.0.0.1");
    }

    SECTION("Special addresses") {
        REQUIRE(IPv4Address::any().is_any());
        REQUIRE(IPv4Address::loopback().is_loopback());
    }

    SECTION("Private address detection") {
        REQUIRE(IPv4Address(10, 0, 0, 1).is_private());
        REQUIRE(IPv4Address(172, 16, 0, 1).is_private());
        REQUIRE(IPv4Address(192, 168, 1, 1).is_private());
        REQUIRE_FALSE(IPv4Address(8, 8, 8, 8).is_private());
    }

    SECTION("Comparison") {
        IPv4Address addr1(192, 168, 1, 1);
        IPv4Address addr2(192, 168, 1, 1);
        IPv4Address addr3(192, 168, 1, 2);

        REQUIRE(addr1 == addr2);
        REQUIRE(addr1 != addr3);
        REQUIRE(addr1 < addr3);
    }
}

TEST_CASE("IPv6Address parsing and operations", "[net][address]") {
    SECTION("Parse valid IPv6") {
        auto addr = IPv6Address::parse("::1");
        REQUIRE(addr.has_value());
        REQUIRE(addr->is_loopback());
    }

    SECTION("Parse full IPv6") {
        auto addr = IPv6Address::parse("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        REQUIRE(addr.has_value());
    }

    SECTION("Special addresses") {
        REQUIRE(IPv6Address::any().is_any());
        REQUIRE(IPv6Address::loopback().is_loopback());
    }

    SECTION("V4-mapped detection") {
        auto addr = IPv6Address::parse("::ffff:192.168.1.1");
        REQUIRE(addr.has_value());
        REQUIRE(addr->is_v4_mapped());

        auto v4 = addr->to_v4();
        REQUIRE(v4.has_value());
        REQUIRE(v4->to_string() == "192.168.1.1");
    }
}

TEST_CASE("SocketAddress parsing", "[net][address]") {
    SECTION("Parse IPv4 socket address") {
        auto addr = SocketAddress::parse("192.168.1.1:51820");
        REQUIRE(addr.has_value());
        REQUIRE(addr->address().is_v4());
        REQUIRE(addr->port() == 51820);
    }

    SECTION("Parse IPv6 socket address") {
        auto addr = SocketAddress::parse("[::1]:51820");
        REQUIRE(addr.has_value());
        REQUIRE(addr->address().is_v6());
        REQUIRE(addr->port() == 51820);
    }

    SECTION("Invalid formats") {
        REQUIRE_FALSE(SocketAddress::parse("192.168.1.1").has_value());  // No port
        REQUIRE_FALSE(SocketAddress::parse(":51820").has_value());       // No address
        REQUIRE_FALSE(SocketAddress::parse("[::1:51820").has_value());   // Missing ]
    }

    SECTION("to_string round trip") {
        auto addr = SocketAddress::parse("10.0.0.1:8080");
        REQUIRE(addr.has_value());
        REQUIRE(addr->to_string() == "10.0.0.1:8080");
    }
}

TEST_CASE("Subnet parsing and containment", "[net][address]") {
    SECTION("Parse IPv4 subnet") {
        auto subnet = Subnet::parse("192.168.1.0/24");
        REQUIRE(subnet.has_value());
        REQUIRE(subnet->prefix_length() == 24);
    }

    SECTION("Parse IPv6 subnet") {
        auto subnet = Subnet::parse("2001:db8::/32");
        REQUIRE(subnet.has_value());
        REQUIRE(subnet->prefix_length() == 32);
    }

    SECTION("IPv4 containment") {
        auto subnet = Subnet::parse("10.0.0.0/8");
        REQUIRE(subnet.has_value());

        REQUIRE(subnet->contains(IpAddress(IPv4Address(10, 0, 0, 1))));
        REQUIRE(subnet->contains(IpAddress(IPv4Address(10, 255, 255, 255))));
        REQUIRE_FALSE(subnet->contains(IpAddress(IPv4Address(11, 0, 0, 1))));
    }

    SECTION("IPv6 containment") {
        auto subnet = Subnet::parse("2001:db8::/32");
        REQUIRE(subnet.has_value());

        auto in_subnet = IPv6Address::parse("2001:db8::1");
        auto out_subnet = IPv6Address::parse("2001:db9::1");

        REQUIRE(in_subnet.has_value());
        REQUIRE(out_subnet.has_value());

        REQUIRE(subnet->contains(IpAddress(*in_subnet)));
        REQUIRE_FALSE(subnet->contains(IpAddress(*out_subnet)));
    }

    SECTION("Host address (no slash)") {
        auto subnet = Subnet::parse("192.168.1.1");
        REQUIRE(subnet.has_value());
        REQUIRE(subnet->prefix_length() == 32);
    }
}

TEST_CASE("UdpSocket basic operations", "[net][udp]") {
    SECTION("Create and bind socket") {
        UdpSocket sock;
        REQUIRE(sock.bind_any(0));
        REQUIRE(sock.is_open());

        auto local = sock.local_address();
        REQUIRE(local.has_value());
        REQUIRE(local->port() != 0);
    }

    SECTION("Send and receive") {
        UdpSocket sender;
        UdpSocket receiver;

        REQUIRE(receiver.bind(SocketAddress(IPv4Address::loopback(), 0)));
        auto recv_addr = receiver.local_address();
        REQUIRE(recv_addr.has_value());

        REQUIRE(sender.bind(SocketAddress(IPv4Address::loopback(), 0)));

        receiver.set_nonblocking(true);

        std::vector<uint8_t> message = {0x01, 0x02, 0x03, 0x04};
        REQUIRE(sender.send_to(message, *recv_addr));

        // Give it a moment
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        auto result = receiver.try_recv_from();
        REQUIRE(result.has_value());
        REQUIRE(result->data == message);
    }

    SECTION("Move semantics") {
        UdpSocket sock1;
        REQUIRE(sock1.bind_any(0));
        int fd = sock1.fd();

        UdpSocket sock2 = std::move(sock1);
        REQUIRE_FALSE(sock1.is_open());
        REQUIRE(sock2.is_open());
        REQUIRE(sock2.fd() == fd);
    }
}
