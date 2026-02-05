#pragma once

#include "address.hpp"
#include <string>
#include <optional>
#include <span>
#include <vector>

namespace vpn::net {

// Platform-independent TUN device interface
class TunDevice {
public:
    TunDevice();
    ~TunDevice();

    // Non-copyable
    TunDevice(const TunDevice&) = delete;
    TunDevice& operator=(const TunDevice&) = delete;

    // Movable
    TunDevice(TunDevice&& other) noexcept;
    TunDevice& operator=(TunDevice&& other) noexcept;

    // Create and open a TUN device
    // name: requested interface name (Linux: e.g. "wg0", macOS: ignored, uses utun)
    bool open(const std::string& name = "");

    // Close the device
    void close();

    // Check if device is open
    bool is_open() const { return fd_ >= 0; }

    // Get device name
    const std::string& name() const { return name_; }

    // Get file descriptor for polling
    int fd() const { return fd_; }

    // Set device MTU
    bool set_mtu(int mtu);

    // Get device MTU
    int mtu() const { return mtu_; }

    // Add IPv4 address to interface
    bool add_address(const IPv4Address& addr, uint8_t prefix_len);

    // Add IPv6 address to interface
    bool add_address(const IPv6Address& addr, uint8_t prefix_len);

    // Bring interface up
    bool up();

    // Bring interface down
    bool down();

    // Read a packet from the TUN device
    // Returns the packet data or nullopt on error/would block
    std::optional<std::vector<uint8_t>> read();

    // Read into existing buffer
    // Returns number of bytes read, 0 if would block, -1 on error
    ssize_t read_into(std::span<uint8_t> buffer);

    // Write a packet to the TUN device
    bool write(std::span<const uint8_t> packet);

    // Set non-blocking mode
    bool set_nonblocking(bool nonblocking);

private:
#ifdef __APPLE__
    bool open_macos(const std::string& name);
#else
    bool open_linux(const std::string& name);
#endif

    int fd_ = -1;
    std::string name_;
    int mtu_ = 1420;  // WireGuard default MTU
};

} // namespace vpn::net
