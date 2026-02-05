#include "vpn/net/udp_socket.hpp"
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cerrno>
#include <cstring>

namespace vpn::net {

UdpSocket::UdpSocket() = default;

UdpSocket::UdpSocket(UdpSocket&& other) noexcept
    : fd_v4_(other.fd_v4_), fd_v6_(other.fd_v6_), nonblocking_(other.nonblocking_) {
    other.fd_v4_ = -1;
    other.fd_v6_ = -1;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
    if (this != &other) {
        close();
        fd_v4_ = other.fd_v4_;
        fd_v6_ = other.fd_v6_;
        nonblocking_ = other.nonblocking_;
        other.fd_v4_ = -1;
        other.fd_v6_ = -1;
    }
    return *this;
}

UdpSocket::~UdpSocket() {
    close();
}

bool UdpSocket::create_v4_socket() {
    if (fd_v4_ >= 0) return true;

    fd_v4_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_v4_ < 0) return false;

    if (!set_socket_options(fd_v4_)) {
        ::close(fd_v4_);
        fd_v4_ = -1;
        return false;
    }

    return true;
}

bool UdpSocket::create_v6_socket() {
    if (fd_v6_ >= 0) return true;

    fd_v6_ = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd_v6_ < 0) return false;

    // Disable dual-stack to have separate v4 and v6 sockets
    int v6only = 1;
    setsockopt(fd_v6_, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

    if (!set_socket_options(fd_v6_)) {
        ::close(fd_v6_);
        fd_v6_ = -1;
        return false;
    }

    return true;
}

bool UdpSocket::set_socket_options(int fd) {
    // Allow address reuse
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        return false;
    }

#ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        // Not critical, continue
    }
#endif

    return true;
}

bool UdpSocket::bind(const SocketAddress& addr) {
    sockaddr_storage storage;
    socklen_t len = addr.to_sockaddr(&storage);

    if (addr.address().is_v4()) {
        if (!create_v4_socket()) return false;

        if (::bind(fd_v4_, reinterpret_cast<sockaddr*>(&storage), len) < 0) {
            return false;
        }
    } else {
        if (!create_v6_socket()) return false;

        if (::bind(fd_v6_, reinterpret_cast<sockaddr*>(&storage), len) < 0) {
            return false;
        }
    }

    return true;
}

bool UdpSocket::bind_any(uint16_t port) {
    // Try to bind both IPv4 and IPv6
    bool v4_ok = false;
    bool v6_ok = false;

    // IPv4
    if (create_v4_socket()) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (::bind(fd_v4_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            v4_ok = true;
        } else {
            ::close(fd_v4_);
            fd_v4_ = -1;
        }
    }

    // IPv6
    if (create_v6_socket()) {
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        addr.sin6_addr = in6addr_any;

        if (::bind(fd_v6_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            v6_ok = true;
        } else {
            ::close(fd_v6_);
            fd_v6_ = -1;
        }
    }

    // Need at least one socket bound
    return v4_ok || v6_ok;
}

bool UdpSocket::send_to(std::span<const uint8_t> data, const SocketAddress& to) {
    sockaddr_storage storage;
    socklen_t len = to.to_sockaddr(&storage);

    int fd = to.address().is_v4() ? fd_v4_ : fd_v6_;
    if (fd < 0) return false;

    ssize_t sent = sendto(fd, data.data(), data.size(), 0,
                          reinterpret_cast<sockaddr*>(&storage), len);

    return sent == static_cast<ssize_t>(data.size());
}

std::optional<RecvResult> UdpSocket::recv_from() {
    std::vector<uint8_t> buffer(MAX_PACKET_SIZE);
    sockaddr_storage storage;
    socklen_t storage_len = sizeof(storage);

    // Try to receive from either socket
    int fd = fd_v6_ >= 0 ? fd_v6_ : fd_v4_;
    if (fd < 0) return std::nullopt;

    ssize_t received = recvfrom(fd, buffer.data(), buffer.size(), 0,
                                reinterpret_cast<sockaddr*>(&storage), &storage_len);

    if (received < 0) {
        // Try other socket if available
        if (fd == fd_v6_ && fd_v4_ >= 0) {
            storage_len = sizeof(storage);
            received = recvfrom(fd_v4_, buffer.data(), buffer.size(), 0,
                               reinterpret_cast<sockaddr*>(&storage), &storage_len);
        }
        if (received < 0) return std::nullopt;
    }

    buffer.resize(static_cast<size_t>(received));
    return RecvResult{
        std::move(buffer),
        SocketAddress::from_sockaddr(reinterpret_cast<sockaddr*>(&storage), storage_len)
    };
}

std::optional<RecvResult> UdpSocket::try_recv_from() {
    if (!nonblocking_) {
        set_nonblocking(true);
    }

    auto result = recv_from();
    if (!result && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return std::nullopt;
    }
    return result;
}

ssize_t UdpSocket::recv_from_into(std::span<uint8_t> buffer, SocketAddress& from) {
    sockaddr_storage storage;
    socklen_t storage_len = sizeof(storage);

    int fd = fd_v6_ >= 0 ? fd_v6_ : fd_v4_;
    if (fd < 0) return -1;

    ssize_t received = recvfrom(fd, buffer.data(), buffer.size(), 0,
                                reinterpret_cast<sockaddr*>(&storage), &storage_len);

    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Try other socket
            if (fd == fd_v6_ && fd_v4_ >= 0) {
                storage_len = sizeof(storage);
                received = recvfrom(fd_v4_, buffer.data(), buffer.size(), 0,
                                   reinterpret_cast<sockaddr*>(&storage), &storage_len);
                if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    return 0;
                }
            } else {
                return 0;
            }
        }
        if (received < 0) return -1;
    }

    from = SocketAddress::from_sockaddr(reinterpret_cast<sockaddr*>(&storage), storage_len);
    return received;
}

bool UdpSocket::set_nonblocking(bool nonblocking) {
    auto set_nb = [nonblocking](int fd) -> bool {
        if (fd < 0) return true;

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) return false;

        if (nonblocking) {
            flags |= O_NONBLOCK;
        } else {
            flags &= ~O_NONBLOCK;
        }

        return fcntl(fd, F_SETFL, flags) == 0;
    };

    bool ok = true;
    if (fd_v4_ >= 0) ok &= set_nb(fd_v4_);
    if (fd_v6_ >= 0) ok &= set_nb(fd_v6_);

    if (ok) nonblocking_ = nonblocking;
    return ok;
}

bool UdpSocket::set_recv_buffer_size(size_t size) {
    int sz = static_cast<int>(size);

    bool ok = true;
    if (fd_v4_ >= 0) {
        ok &= setsockopt(fd_v4_, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)) == 0;
    }
    if (fd_v6_ >= 0) {
        ok &= setsockopt(fd_v6_, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)) == 0;
    }
    return ok;
}

bool UdpSocket::set_send_buffer_size(size_t size) {
    int sz = static_cast<int>(size);

    bool ok = true;
    if (fd_v4_ >= 0) {
        ok &= setsockopt(fd_v4_, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)) == 0;
    }
    if (fd_v6_ >= 0) {
        ok &= setsockopt(fd_v6_, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)) == 0;
    }
    return ok;
}

void UdpSocket::close() {
    if (fd_v4_ >= 0) {
        ::close(fd_v4_);
        fd_v4_ = -1;
    }
    if (fd_v6_ >= 0) {
        ::close(fd_v6_);
        fd_v6_ = -1;
    }
}

std::optional<SocketAddress> UdpSocket::local_address() const {
    int fd = fd_v6_ >= 0 ? fd_v6_ : fd_v4_;
    if (fd < 0) return std::nullopt;

    sockaddr_storage storage;
    socklen_t len = sizeof(storage);

    if (getsockname(fd, reinterpret_cast<sockaddr*>(&storage), &len) < 0) {
        return std::nullopt;
    }

    return SocketAddress::from_sockaddr(reinterpret_cast<sockaddr*>(&storage), len);
}

} // namespace vpn::net
