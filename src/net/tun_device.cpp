#include "vpn/net/tun_device.hpp"
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>

#ifdef __APPLE__
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#else
#include <linux/if_tun.h>
#endif

namespace vpn::net {

TunDevice::TunDevice() = default;

TunDevice::~TunDevice() {
    close();
}

TunDevice::TunDevice(TunDevice&& other) noexcept
    : fd_(other.fd_), name_(std::move(other.name_)), mtu_(other.mtu_) {
    other.fd_ = -1;
}

TunDevice& TunDevice::operator=(TunDevice&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        name_ = std::move(other.name_);
        mtu_ = other.mtu_;
        other.fd_ = -1;
    }
    return *this;
}

bool TunDevice::open(const std::string& name) {
#ifdef __APPLE__
    return open_macos(name);
#else
    return open_linux(name);
#endif
}

#ifdef __APPLE__

bool TunDevice::open_macos(const std::string& name) {
    // On macOS, we use the utun kernel control interface
    fd_ = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd_ < 0) {
        return false;
    }

    // Get the control ID for utun
    ctl_info info{};
    std::strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name) - 1);

    if (ioctl(fd_, CTLIOCGINFO, &info) < 0) {
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    // Connect to a utun device
    sockaddr_ctl addr{};
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;

    // Try to find an available utun number
    for (int i = 0; i < 256; ++i) {
        addr.sc_unit = static_cast<uint32_t>(i + 1);  // utun numbers start at 0 but unit is 1-based
        if (connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            name_ = "utun" + std::to_string(i);
            return true;
        }
    }

    ::close(fd_);
    fd_ = -1;
    return false;
}

#else  // Linux

bool TunDevice::open_linux(const std::string& name) {
    fd_ = ::open("/dev/net/tun", O_RDWR);
    if (fd_ < 0) {
        return false;
    }

    ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  // TUN device, no packet info header

    if (!name.empty()) {
        std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    }

    if (ioctl(fd_, TUNSETIFF, &ifr) < 0) {
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    name_ = ifr.ifr_name;
    return true;
}

#endif

void TunDevice::close() {
    if (fd_ >= 0) {
        down();
        ::close(fd_);
        fd_ = -1;
    }
    name_.clear();
}

bool TunDevice::set_mtu(int mtu) {
    if (!is_open()) return false;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);
    ifr.ifr_mtu = mtu;

    bool ok = ioctl(sock, SIOCSIFMTU, &ifr) == 0;
    ::close(sock);

    if (ok) mtu_ = mtu;
    return ok;
}

bool TunDevice::add_address(const IPv4Address& addr, uint8_t prefix_len) {
    if (!is_open()) return false;

    // Use system command for simplicity and portability
    char cmd[256];
#ifdef __APPLE__
    snprintf(cmd, sizeof(cmd), "ifconfig %s inet %s/%d alias",
             name_.c_str(), addr.to_string().c_str(), prefix_len);
#else
    snprintf(cmd, sizeof(cmd), "ip addr add %s/%d dev %s",
             addr.to_string().c_str(), prefix_len, name_.c_str());
#endif

    return system(cmd) == 0;
}

bool TunDevice::add_address(const IPv6Address& addr, uint8_t prefix_len) {
    if (!is_open()) return false;

    char cmd[256];
#ifdef __APPLE__
    snprintf(cmd, sizeof(cmd), "ifconfig %s inet6 %s/%d alias",
             name_.c_str(), addr.to_string().c_str(), prefix_len);
#else
    snprintf(cmd, sizeof(cmd), "ip -6 addr add %s/%d dev %s",
             addr.to_string().c_str(), prefix_len, name_.c_str());
#endif

    return system(cmd) == 0;
}

bool TunDevice::up() {
    if (!is_open()) return false;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);

    // Get current flags
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        ::close(sock);
        return false;
    }

    // Set UP flag
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    bool ok = ioctl(sock, SIOCSIFFLAGS, &ifr) == 0;
    ::close(sock);
    return ok;
}

bool TunDevice::down() {
    if (!is_open()) return false;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);

    // Get current flags
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        ::close(sock);
        return false;
    }

    // Clear UP flag
    ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);

    bool ok = ioctl(sock, SIOCSIFFLAGS, &ifr) == 0;
    ::close(sock);
    return ok;
}

std::optional<std::vector<uint8_t>> TunDevice::read() {
    std::vector<uint8_t> buffer(mtu_ + 100);  // Extra space for headers
    ssize_t n = read_into(buffer);

    if (n <= 0) return std::nullopt;

    buffer.resize(static_cast<size_t>(n));
    return buffer;
}

ssize_t TunDevice::read_into(std::span<uint8_t> buffer) {
    if (!is_open()) return -1;

#ifdef __APPLE__
    // macOS utun prepends a 4-byte protocol header
    std::vector<uint8_t> temp(buffer.size() + 4);
    ssize_t n = ::read(fd_, temp.data(), temp.size());

    if (n < 4) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        }
        return n;
    }

    // Skip the 4-byte header
    size_t payload_size = static_cast<size_t>(n) - 4;
    std::memcpy(buffer.data(), temp.data() + 4, std::min(payload_size, buffer.size()));
    return static_cast<ssize_t>(std::min(payload_size, buffer.size()));
#else
    ssize_t n = ::read(fd_, buffer.data(), buffer.size());
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return 0;
    }
    return n;
#endif
}

bool TunDevice::write(std::span<const uint8_t> packet) {
    if (!is_open()) return false;

#ifdef __APPLE__
    // macOS utun requires a 4-byte protocol header
    std::vector<uint8_t> buffer(4 + packet.size());

    // Determine protocol from IP header
    if (!packet.empty()) {
        uint8_t version = (packet[0] >> 4) & 0x0F;
        if (version == 4) {
            buffer[3] = AF_INET;
        } else if (version == 6) {
            buffer[3] = AF_INET6;
        }
    }

    std::memcpy(buffer.data() + 4, packet.data(), packet.size());
    return ::write(fd_, buffer.data(), buffer.size()) == static_cast<ssize_t>(buffer.size());
#else
    return ::write(fd_, packet.data(), packet.size()) == static_cast<ssize_t>(packet.size());
#endif
}

bool TunDevice::set_nonblocking(bool nonblocking) {
    if (!is_open()) return false;

    int flags = fcntl(fd_, F_GETFL, 0);
    if (flags < 0) return false;

    if (nonblocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }

    return fcntl(fd_, F_SETFL, flags) == 0;
}

} // namespace vpn::net
