#pragma once

#include "address.hpp"
#include <vector>
#include <optional>
#include <span>
#include <functional>

namespace vpn::net {

// Result of a receive operation
struct RecvResult {
    std::vector<uint8_t> data;
    SocketAddress from;
};

// UDP socket supporting both IPv4 and IPv6
class UdpSocket {
public:
    // Create an unbound socket
    UdpSocket();

    // Non-copyable
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    // Movable
    UdpSocket(UdpSocket&& other) noexcept;
    UdpSocket& operator=(UdpSocket&& other) noexcept;

    ~UdpSocket();

    // Bind to address (creates socket if needed)
    bool bind(const SocketAddress& addr);

    // Bind to port on all interfaces (dual-stack if possible)
    bool bind_any(uint16_t port);

    // Send data to address
    bool send_to(std::span<const uint8_t> data, const SocketAddress& to);

    // Receive data (blocking)
    std::optional<RecvResult> recv_from();

    // Receive data (non-blocking, returns nullopt if would block)
    std::optional<RecvResult> try_recv_from();

    // Receive into existing buffer
    // Returns number of bytes received, or -1 on error, 0 if would block
    ssize_t recv_from_into(std::span<uint8_t> buffer, SocketAddress& from);

    // Set non-blocking mode
    bool set_nonblocking(bool nonblocking);

    // Set receive buffer size
    bool set_recv_buffer_size(size_t size);

    // Set send buffer size
    bool set_send_buffer_size(size_t size);

    // Get file descriptor for polling
    int fd() const { return fd_v6_ >= 0 ? fd_v6_ : fd_v4_; }

    // Get both file descriptors (for dual-stack)
    int fd_v4() const { return fd_v4_; }
    int fd_v6() const { return fd_v6_; }

    // Check if socket is open
    bool is_open() const { return fd_v4_ >= 0 || fd_v6_ >= 0; }

    // Close socket
    void close();

    // Get bound address
    std::optional<SocketAddress> local_address() const;

    // Maximum UDP payload size
    static constexpr size_t MAX_PACKET_SIZE = 65535 - 8 - 20;  // Max UDP - UDP header - IP header

private:
    bool create_v4_socket();
    bool create_v6_socket();
    bool set_socket_options(int fd);

    int fd_v4_ = -1;
    int fd_v6_ = -1;
    bool nonblocking_ = false;
};

} // namespace vpn::net
