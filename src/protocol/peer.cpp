#include "vpn/protocol/peer.hpp"

namespace vpn::protocol {

Peer::Peer(const PeerConfig& config)
    : public_key_(config.public_key)
    , preshared_key_(config.preshared_key)
    , endpoint_(config.endpoint)
    , allowed_ips_(config.allowed_ips)
{
    if (config.persistent_keepalive.count() > 0) {
        timers_.set_persistent_keepalive(config.persistent_keepalive);
    }
}

std::optional<net::SocketAddress> Peer::endpoint() const {
    std::lock_guard lock(endpoint_mutex_);
    return endpoint_;
}

void Peer::set_endpoint(const net::SocketAddress& endpoint) {
    std::lock_guard lock(endpoint_mutex_);
    endpoint_ = endpoint;
}

bool Peer::is_allowed_ip(const net::IpAddress& addr) const {
    for (const auto& subnet : allowed_ips_) {
        if (subnet.contains(addr)) {
            return true;
        }
    }
    return false;
}

std::shared_ptr<Session> Peer::current_session() const {
    std::lock_guard lock(session_mutex_);
    return current_session_;
}

std::shared_ptr<Session> Peer::previous_session() const {
    std::lock_guard lock(session_mutex_);
    return previous_session_;
}

void Peer::set_current_session(std::shared_ptr<Session> session) {
    std::lock_guard lock(session_mutex_);
    current_session_ = std::move(session);
}

void Peer::rotate_session(std::shared_ptr<Session> new_session) {
    std::lock_guard lock(session_mutex_);
    previous_session_ = std::move(current_session_);
    current_session_ = std::move(new_session);
}

std::shared_ptr<Session> Peer::session_by_index(uint32_t index) const {
    std::lock_guard lock(session_mutex_);

    if (current_session_ && current_session_->local_index() == index) {
        return current_session_;
    }
    if (previous_session_ && previous_session_->local_index() == index) {
        return previous_session_;
    }
    return nullptr;
}

void Peer::reset_handshake(const crypto::Curve25519KeyPair& local_static) {
    handshake_ = crypto::NoiseHandshake::create_initiator(
        local_static,
        public_key_,
        preshared_key_
    );
}

bool Peer::check_replay_timestamp(const crypto::Tai64nTimestamp& timestamp) {
    std::lock_guard lock(replay_mutex_);

    if (last_timestamp_ && !timestamp.operator>(*last_timestamp_)) {
        return false;  // Replay or old timestamp
    }

    last_timestamp_ = timestamp;
    return true;
}

void Peer::set_cookie(const std::array<uint8_t, 16>& cookie) {
    std::lock_guard lock(cookie_mutex_);
    cookie_ = cookie;
    cookie_time_ = std::chrono::steady_clock::now();
}

std::optional<std::array<uint8_t, 16>> Peer::cookie() const {
    std::lock_guard lock(cookie_mutex_);
    if (!cookie_valid()) {
        return std::nullopt;
    }
    return cookie_;
}

bool Peer::cookie_valid() const {
    if (!cookie_) return false;

    auto age = std::chrono::steady_clock::now() - cookie_time_;
    // Cookies are valid for 120 seconds
    return age < std::chrono::seconds(120);
}

void Peer::add_rx_bytes(size_t bytes) {
    std::lock_guard lock(stats_mutex_);
    stats_.rx_bytes += bytes;
    stats_.rx_packets++;
}

void Peer::add_tx_bytes(size_t bytes) {
    std::lock_guard lock(stats_mutex_);
    stats_.tx_bytes += bytes;
    stats_.tx_packets++;
}

Peer::Stats Peer::stats() const {
    std::lock_guard lock(stats_mutex_);
    return stats_;
}

} // namespace vpn::protocol
