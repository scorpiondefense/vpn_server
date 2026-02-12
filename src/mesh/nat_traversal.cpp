#include "vpn/mesh/nat_traversal.hpp"
#include "vpn/util/logger.hpp"
#include <algorithm>
#include <cstring>

namespace vpn::mesh {

// --- NatDiscovery ---

void NatDiscovery::set_reflexive_address(const net::SocketAddress& addr) {
    std::lock_guard lock(mutex_);
    result_.reflexive_address = addr;
}

void NatDiscovery::set_local_address(const net::SocketAddress& addr) {
    std::lock_guard lock(mutex_);
    result_.local_address = addr;
}

NatDiscoveryResult NatDiscovery::result() const {
    std::lock_guard lock(mutex_);
    auto r = result_;
    r.type = classify();
    return r;
}

NatType NatDiscovery::classify() const {
    // Simple classification based on available data
    if (!result_.reflexive_address) {
        return NatType::Unknown;
    }

    if (!result_.local_address) {
        return NatType::Unknown;
    }

    // Compare local and reflexive addresses
    if (result_.local_address->address() == result_.reflexive_address->address() &&
        result_.local_address->port() == result_.reflexive_address->port()) {
        return NatType::OpenInternet;
    }

    if (result_.local_address->address() == result_.reflexive_address->address()) {
        // Same IP, different port — likely port-restricted or symmetric
        return NatType::PortRestricted;
    }

    // Different IP — behind NAT, assume restricted cone as default
    return NatType::RestrictedCone;
}

std::vector<net::SocketAddress> NatDiscovery::build_endpoint_list() const {
    std::lock_guard lock(mutex_);
    std::vector<net::SocketAddress> endpoints;

    if (result_.reflexive_address) {
        endpoints.push_back(*result_.reflexive_address);
    }
    if (result_.local_address) {
        // Only add local if different from reflexive
        if (!result_.reflexive_address || *result_.local_address != *result_.reflexive_address) {
            endpoints.push_back(*result_.local_address);
        }
    }

    return endpoints;
}

// --- HolePuncher ---

HolePuncher::HolePuncher(SendCallback send_cb)
    : send_cb_(std::move(send_cb)) {}

void HolePuncher::initiate(const NodeInfo& target_info, uint64_t punch_nonce) {
    std::lock_guard lock(mutex_);

    // Check if we already have an attempt for this target
    for (const auto& attempt : attempts_) {
        if (attempt.target_node_id == target_info.node_id) {
            return;  // Already attempting
        }
    }

    PunchAttempt attempt;
    attempt.target_node_id = target_info.node_id;
    attempt.target_public_key = target_info.public_key;
    attempt.target_endpoints = target_info.endpoints;
    attempt.punch_nonce = punch_nonce;
    attempt.started_at = std::chrono::steady_clock::now();
    attempt.attempts_remaining = MAX_PUNCH_ATTEMPTS;

    attempts_.push_back(attempt);

    LOG_INFO("NAT: initiating hole punch to node, {} endpoints to try",
             target_info.endpoints.size());
}

void HolePuncher::handle_punch_notify(const MeshPunchNotify& notify) {
    // Start punching toward the notified peer
    initiate(notify.requester_info, notify.punch_nonce);
}

void HolePuncher::tick() {
    std::lock_guard lock(mutex_);
    auto now = std::chrono::steady_clock::now();

    for (auto it = attempts_.begin(); it != attempts_.end(); ) {
        if (it->succeeded || it->attempts_remaining <= 0) {
            it = attempts_.erase(it);
            continue;
        }

        // Send a small probe packet to each endpoint
        // The probe is just the punch nonce as a minimal packet
        // The WireGuard handshake will be triggered separately
        std::vector<uint8_t> probe(8);
        std::memcpy(probe.data(), &it->punch_nonce, 8);

        for (const auto& endpoint : it->target_endpoints) {
            send_cb_(probe, endpoint);
        }

        it->attempts_remaining--;
        ++it;
    }

    // Remove expired attempts (older than 10 seconds)
    attempts_.erase(
        std::remove_if(attempts_.begin(), attempts_.end(),
            [&now](const auto& a) {
                return now - a.started_at > std::chrono::seconds(10);
            }),
        attempts_.end()
    );
}

bool HolePuncher::has_succeeded(const NodeId& target) const {
    std::lock_guard lock(mutex_);
    for (const auto& attempt : attempts_) {
        if (attempt.target_node_id == target && attempt.succeeded) {
            return true;
        }
    }
    return false;
}

size_t HolePuncher::active_attempts() const {
    std::lock_guard lock(mutex_);
    return attempts_.size();
}

// --- RelayManager ---

void RelayManager::add_relay(const NodeId& target, const crypto::PublicKey& relay_key) {
    std::lock_guard lock(mutex_);

    // Check if relay already exists
    for (auto& route : routes_) {
        if (route.target_node_id == target) {
            route.relay_peer_key = relay_key;
            route.established_at = std::chrono::steady_clock::now();
            return;
        }
    }

    routes_.push_back(RelayRoute{
        target,
        relay_key,
        std::chrono::steady_clock::now()
    });
}

void RelayManager::remove_relay(const NodeId& target) {
    std::lock_guard lock(mutex_);
    routes_.erase(
        std::remove_if(routes_.begin(), routes_.end(),
            [&target](const auto& r) { return r.target_node_id == target; }),
        routes_.end()
    );
}

std::optional<crypto::PublicKey> RelayManager::find_relay(const NodeId& target) const {
    std::lock_guard lock(mutex_);
    for (const auto& route : routes_) {
        if (route.target_node_id == target) {
            return route.relay_peer_key;
        }
    }
    return std::nullopt;
}

bool RelayManager::has_relay(const NodeId& target) const {
    std::lock_guard lock(mutex_);
    for (const auto& route : routes_) {
        if (route.target_node_id == target) {
            return true;
        }
    }
    return false;
}

std::vector<RelayManager::RelayRoute> RelayManager::all_routes() const {
    std::lock_guard lock(mutex_);
    return routes_;
}

} // namespace vpn::mesh
