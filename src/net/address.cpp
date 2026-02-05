#include "vpn/net/address.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <sstream>
#include <charconv>

namespace vpn::net {

// IPv4Address implementation

IPv4Address::IPv4Address(uint32_t addr) {
    addr_[0] = static_cast<uint8_t>((addr >> 24) & 0xFF);
    addr_[1] = static_cast<uint8_t>((addr >> 16) & 0xFF);
    addr_[2] = static_cast<uint8_t>((addr >> 8) & 0xFF);
    addr_[3] = static_cast<uint8_t>(addr & 0xFF);
}

IPv4Address::IPv4Address(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    addr_[0] = a;
    addr_[1] = b;
    addr_[2] = c;
    addr_[3] = d;
}

std::optional<IPv4Address> IPv4Address::parse(std::string_view str) {
    in_addr addr;
    std::string str_copy(str);
    if (inet_pton(AF_INET, str_copy.c_str(), &addr) != 1) {
        return std::nullopt;
    }
    return IPv4Address(ntohl(addr.s_addr));
}

uint32_t IPv4Address::to_uint32() const {
    return (static_cast<uint32_t>(addr_[0]) << 24) |
           (static_cast<uint32_t>(addr_[1]) << 16) |
           (static_cast<uint32_t>(addr_[2]) << 8) |
           static_cast<uint32_t>(addr_[3]);
}

std::string IPv4Address::to_string() const {
    std::ostringstream oss;
    oss << static_cast<int>(addr_[0]) << "."
        << static_cast<int>(addr_[1]) << "."
        << static_cast<int>(addr_[2]) << "."
        << static_cast<int>(addr_[3]);
    return oss.str();
}

std::array<uint8_t, 4> IPv4Address::bytes() const {
    return addr_;
}

bool IPv4Address::is_private() const {
    // 10.0.0.0/8
    if (addr_[0] == 10) return true;
    // 172.16.0.0/12
    if (addr_[0] == 172 && (addr_[1] >= 16 && addr_[1] <= 31)) return true;
    // 192.168.0.0/16
    if (addr_[0] == 192 && addr_[1] == 168) return true;
    return false;
}

// IPv6Address implementation

IPv6Address::IPv6Address(const std::array<uint8_t, 16>& bytes) : addr_(bytes) {}

IPv6Address::IPv6Address(const uint8_t* bytes) {
    std::memcpy(addr_.data(), bytes, 16);
}

std::optional<IPv6Address> IPv6Address::parse(std::string_view str) {
    in6_addr addr;
    std::string str_copy(str);
    if (inet_pton(AF_INET6, str_copy.c_str(), &addr) != 1) {
        return std::nullopt;
    }
    return IPv6Address(addr.s6_addr);
}

IPv6Address IPv6Address::any() {
    return IPv6Address(std::array<uint8_t, 16>{});
}

IPv6Address IPv6Address::loopback() {
    std::array<uint8_t, 16> addr{};
    addr[15] = 1;
    return IPv6Address(addr);
}

std::string IPv6Address::to_string() const {
    char buf[INET6_ADDRSTRLEN];
    in6_addr addr;
    std::memcpy(addr.s6_addr, addr_.data(), 16);
    inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    return buf;
}

bool IPv6Address::is_any() const {
    for (auto b : addr_) {
        if (b != 0) return false;
    }
    return true;
}

bool IPv6Address::is_loopback() const {
    for (size_t i = 0; i < 15; ++i) {
        if (addr_[i] != 0) return false;
    }
    return addr_[15] == 1;
}

bool IPv6Address::is_link_local() const {
    return addr_[0] == 0xFE && (addr_[1] & 0xC0) == 0x80;
}

bool IPv6Address::is_v4_mapped() const {
    // ::ffff:x.x.x.x
    for (size_t i = 0; i < 10; ++i) {
        if (addr_[i] != 0) return false;
    }
    return addr_[10] == 0xFF && addr_[11] == 0xFF;
}

std::optional<IPv4Address> IPv6Address::to_v4() const {
    if (!is_v4_mapped()) return std::nullopt;
    return IPv4Address(addr_[12], addr_[13], addr_[14], addr_[15]);
}

// IpAddress implementation

std::optional<IpAddress> IpAddress::parse(std::string_view str) {
    // Try IPv4 first
    if (auto v4 = IPv4Address::parse(str)) {
        return IpAddress(*v4);
    }
    // Try IPv6
    if (auto v6 = IPv6Address::parse(str)) {
        return IpAddress(*v6);
    }
    return std::nullopt;
}

std::string IpAddress::to_string() const {
    if (is_v4()) {
        return as_v4().to_string();
    }
    return as_v6().to_string();
}

// SocketAddress implementation

SocketAddress::SocketAddress(IpAddress addr, uint16_t port)
    : addr_(addr), port_(port) {}

SocketAddress::SocketAddress(IPv4Address addr, uint16_t port)
    : addr_(addr), port_(port) {}

SocketAddress::SocketAddress(IPv6Address addr, uint16_t port)
    : addr_(addr), port_(port) {}

std::optional<SocketAddress> SocketAddress::parse(std::string_view str) {
    // Handle IPv6 [ip]:port format
    if (!str.empty() && str[0] == '[') {
        auto close_bracket = str.find(']');
        if (close_bracket == std::string_view::npos) {
            return std::nullopt;
        }
        auto ip_str = str.substr(1, close_bracket - 1);
        auto rest = str.substr(close_bracket + 1);

        if (rest.empty() || rest[0] != ':') {
            return std::nullopt;
        }
        auto port_str = rest.substr(1);

        auto ip = IPv6Address::parse(ip_str);
        if (!ip) return std::nullopt;

        uint16_t port;
        auto result = std::from_chars(port_str.data(), port_str.data() + port_str.size(), port);
        if (result.ec != std::errc{}) return std::nullopt;

        return SocketAddress(*ip, port);
    }

    // Handle IPv4 ip:port format
    auto colon = str.rfind(':');
    if (colon == std::string_view::npos) {
        return std::nullopt;
    }

    auto ip_str = str.substr(0, colon);
    auto port_str = str.substr(colon + 1);

    auto ip = IpAddress::parse(ip_str);
    if (!ip) return std::nullopt;

    uint16_t port;
    auto result = std::from_chars(port_str.data(), port_str.data() + port_str.size(), port);
    if (result.ec != std::errc{}) return std::nullopt;

    return SocketAddress(*ip, port);
}

SocketAddress SocketAddress::from_sockaddr(const sockaddr* addr, socklen_t len) {
    if (addr->sa_family == AF_INET && len >= sizeof(sockaddr_in)) {
        return from_sockaddr_in(*reinterpret_cast<const sockaddr_in*>(addr));
    } else if (addr->sa_family == AF_INET6 && len >= sizeof(sockaddr_in6)) {
        return from_sockaddr_in6(*reinterpret_cast<const sockaddr_in6*>(addr));
    }
    return SocketAddress();
}

SocketAddress SocketAddress::from_sockaddr_in(const sockaddr_in& addr) {
    return SocketAddress(
        IPv4Address(ntohl(addr.sin_addr.s_addr)),
        ntohs(addr.sin_port)
    );
}

SocketAddress SocketAddress::from_sockaddr_in6(const sockaddr_in6& addr) {
    return SocketAddress(
        IPv6Address(addr.sin6_addr.s6_addr),
        ntohs(addr.sin6_port)
    );
}

std::string SocketAddress::to_string() const {
    if (addr_.is_v6()) {
        return "[" + addr_.to_string() + "]:" + std::to_string(port_);
    }
    return addr_.to_string() + ":" + std::to_string(port_);
}

socklen_t SocketAddress::to_sockaddr(sockaddr_storage* storage) const {
    std::memset(storage, 0, sizeof(*storage));

    if (addr_.is_v4()) {
        auto* sin = reinterpret_cast<sockaddr_in*>(storage);
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port_);
        sin->sin_addr.s_addr = htonl(addr_.as_v4().to_uint32());
        return sizeof(sockaddr_in);
    } else {
        auto* sin6 = reinterpret_cast<sockaddr_in6*>(storage);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port_);
        std::memcpy(sin6->sin6_addr.s6_addr, addr_.as_v6().bytes().data(), 16);
        return sizeof(sockaddr_in6);
    }
}

std::vector<uint8_t> SocketAddress::to_bytes() const {
    std::vector<uint8_t> result;
    if (addr_.is_v4()) {
        auto bytes = addr_.as_v4().bytes();
        result.insert(result.end(), bytes.begin(), bytes.end());
    } else {
        const auto& bytes = addr_.as_v6().bytes();
        result.insert(result.end(), bytes.begin(), bytes.end());
    }
    // Append port in big-endian
    result.push_back(static_cast<uint8_t>((port_ >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>(port_ & 0xFF));
    return result;
}

// Subnet implementation

Subnet::Subnet(IpAddress addr, uint8_t prefix_len)
    : addr_(addr), prefix_len_(prefix_len) {}

std::optional<Subnet> Subnet::parse(std::string_view str) {
    auto slash = str.find('/');
    if (slash == std::string_view::npos) {
        // No prefix, assume /32 or /128
        auto ip = IpAddress::parse(str);
        if (!ip) return std::nullopt;
        return Subnet(*ip, ip->is_v4() ? 32 : 128);
    }

    auto ip_str = str.substr(0, slash);
    auto prefix_str = str.substr(slash + 1);

    auto ip = IpAddress::parse(ip_str);
    if (!ip) return std::nullopt;

    uint8_t prefix;
    auto result = std::from_chars(prefix_str.data(), prefix_str.data() + prefix_str.size(), prefix);
    if (result.ec != std::errc{}) return std::nullopt;

    uint8_t max_prefix = ip->is_v4() ? 32 : 128;
    if (prefix > max_prefix) return std::nullopt;

    return Subnet(*ip, prefix);
}

bool Subnet::contains(const IpAddress& addr) const {
    if (addr_.is_v4() != addr.is_v4()) {
        return false;  // Can't compare v4 and v6
    }

    if (addr_.is_v4()) {
        uint32_t mask = prefix_len_ == 0 ? 0 : (~0U << (32 - prefix_len_));
        uint32_t subnet_addr = addr_.as_v4().to_uint32() & mask;
        uint32_t test_addr = addr.as_v4().to_uint32() & mask;
        return subnet_addr == test_addr;
    } else {
        const auto& subnet_bytes = addr_.as_v6().bytes();
        const auto& test_bytes = addr.as_v6().bytes();

        size_t full_bytes = prefix_len_ / 8;
        size_t remaining_bits = prefix_len_ % 8;

        // Compare full bytes
        for (size_t i = 0; i < full_bytes; ++i) {
            if (subnet_bytes[i] != test_bytes[i]) return false;
        }

        // Compare remaining bits
        if (remaining_bits > 0 && full_bytes < 16) {
            uint8_t mask = static_cast<uint8_t>(~0U << (8 - remaining_bits));
            if ((subnet_bytes[full_bytes] & mask) != (test_bytes[full_bytes] & mask)) {
                return false;
            }
        }

        return true;
    }
}

std::string Subnet::to_string() const {
    return addr_.to_string() + "/" + std::to_string(prefix_len_);
}

} // namespace vpn::net
