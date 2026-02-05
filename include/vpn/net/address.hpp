#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <variant>
#include <array>
#include <vector>
#include <cstdint>
#include <compare>

#ifdef __APPLE__
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

namespace vpn::net {

// IPv4 address (4 bytes)
class IPv4Address {
public:
    IPv4Address() = default;
    explicit IPv4Address(uint32_t addr);
    IPv4Address(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

    static std::optional<IPv4Address> parse(std::string_view str);
    static IPv4Address any() { return IPv4Address(0); }
    static IPv4Address loopback() { return IPv4Address(127, 0, 0, 1); }

    uint32_t to_uint32() const;
    std::string to_string() const;
    std::array<uint8_t, 4> bytes() const;

    bool is_any() const { return to_uint32() == 0; }
    bool is_loopback() const { return (to_uint32() & 0xFF000000) == 0x7F000000; }
    bool is_private() const;

    auto operator<=>(const IPv4Address&) const = default;

private:
    std::array<uint8_t, 4> addr_{};
};

// IPv6 address (16 bytes)
class IPv6Address {
public:
    IPv6Address() = default;
    explicit IPv6Address(const std::array<uint8_t, 16>& bytes);
    explicit IPv6Address(const uint8_t* bytes);

    static std::optional<IPv6Address> parse(std::string_view str);
    static IPv6Address any();
    static IPv6Address loopback();

    std::string to_string() const;
    const std::array<uint8_t, 16>& bytes() const { return addr_; }

    bool is_any() const;
    bool is_loopback() const;
    bool is_link_local() const;
    bool is_v4_mapped() const;

    // Extract IPv4 address from ::ffff:x.x.x.x
    std::optional<IPv4Address> to_v4() const;

    auto operator<=>(const IPv6Address&) const = default;

private:
    std::array<uint8_t, 16> addr_{};
};

// Generic IP address (v4 or v6)
class IpAddress {
public:
    IpAddress() : addr_(IPv4Address{}) {}
    IpAddress(IPv4Address addr) : addr_(addr) {}
    IpAddress(IPv6Address addr) : addr_(addr) {}

    static std::optional<IpAddress> parse(std::string_view str);

    bool is_v4() const { return std::holds_alternative<IPv4Address>(addr_); }
    bool is_v6() const { return std::holds_alternative<IPv6Address>(addr_); }

    const IPv4Address& as_v4() const { return std::get<IPv4Address>(addr_); }
    const IPv6Address& as_v6() const { return std::get<IPv6Address>(addr_); }

    std::string to_string() const;

    bool operator==(const IpAddress& other) const { return addr_ == other.addr_; }
    bool operator!=(const IpAddress& other) const { return addr_ != other.addr_; }

private:
    std::variant<IPv4Address, IPv6Address> addr_;
};

// Socket address (IP + port)
class SocketAddress {
public:
    SocketAddress() = default;
    SocketAddress(IpAddress addr, uint16_t port);
    SocketAddress(IPv4Address addr, uint16_t port);
    SocketAddress(IPv6Address addr, uint16_t port);

    // Parse "ip:port" or "[ip]:port" for IPv6
    static std::optional<SocketAddress> parse(std::string_view str);

    // Create from sockaddr
    static SocketAddress from_sockaddr(const sockaddr* addr, socklen_t len);
    static SocketAddress from_sockaddr_in(const sockaddr_in& addr);
    static SocketAddress from_sockaddr_in6(const sockaddr_in6& addr);

    const IpAddress& address() const { return addr_; }
    uint16_t port() const { return port_; }

    std::string to_string() const;

    // Convert to sockaddr for system calls
    socklen_t to_sockaddr(sockaddr_storage* storage) const;

    // Get bytes for cookie computation
    std::vector<uint8_t> to_bytes() const;

    bool operator==(const SocketAddress& other) const {
        return addr_ == other.addr_ && port_ == other.port_;
    }
    bool operator!=(const SocketAddress& other) const {
        return !(*this == other);
    }

private:
    IpAddress addr_;
    uint16_t port_ = 0;
};

// CIDR subnet (for AllowedIPs)
class Subnet {
public:
    Subnet() = default;
    Subnet(IpAddress addr, uint8_t prefix_len);

    static std::optional<Subnet> parse(std::string_view str);

    const IpAddress& address() const { return addr_; }
    uint8_t prefix_length() const { return prefix_len_; }

    // Check if an address is contained in this subnet
    bool contains(const IpAddress& addr) const;

    std::string to_string() const;

    bool operator==(const Subnet& other) const {
        return addr_ == other.addr_ && prefix_len_ == other.prefix_len_;
    }

private:
    IpAddress addr_;
    uint8_t prefix_len_ = 0;
};

} // namespace vpn::net
