#include "vpn/protocol/timer.hpp"
#include <algorithm>

namespace vpn::protocol {

PeerTimers::PeerTimers() {
    reset();
}

void PeerTimers::handshake_initiated() {
    last_handshake_initiation_.store(Clock::now(), std::memory_order_relaxed);
    handshake_in_progress_.store(true, std::memory_order_relaxed);
    handshake_attempts_.fetch_add(1, std::memory_order_relaxed);
}

void PeerTimers::handshake_complete() {
    last_handshake_complete_.store(Clock::now(), std::memory_order_relaxed);
    handshake_in_progress_.store(false, std::memory_order_relaxed);
    session_established_.store(true, std::memory_order_relaxed);
    handshake_attempts_.store(0, std::memory_order_relaxed);
}

void PeerTimers::data_sent() {
    last_data_sent_.store(Clock::now(), std::memory_order_relaxed);
}

void PeerTimers::data_received() {
    last_data_received_.store(Clock::now(), std::memory_order_relaxed);
    any_authenticated_packet_received();
}

void PeerTimers::any_authenticated_packet_received() {
    last_any_authenticated_.store(Clock::now(), std::memory_order_relaxed);
}

std::optional<std::pair<TimerEvent, PeerTimers::Duration>> PeerTimers::next_event() const {
    auto now = Clock::now();

    // Check for handshake retransmit
    if (handshake_in_progress_.load(std::memory_order_relaxed)) {
        auto last_init = last_handshake_initiation_.load(std::memory_order_relaxed);
        auto since_init = now - last_init;

        if (handshake_attempts_.load(std::memory_order_relaxed) >= TimerConstants::MAX_TIMER_HANDSHAKES) {
            // Too many attempts, zero keys
            return std::make_pair(TimerEvent::ZeroKeys, Duration::zero());
        }

        if (since_init >= TimerConstants::REKEY_TIMEOUT) {
            return std::make_pair(TimerEvent::RetransmitHandshake, Duration::zero());
        }

        auto until_retransmit = TimerConstants::REKEY_TIMEOUT - since_init;
        return std::make_pair(TimerEvent::RetransmitHandshake, until_retransmit);
    }

    // Check if session is established
    if (!session_established_.load(std::memory_order_relaxed)) {
        return std::nullopt;
    }

    auto last_complete = last_handshake_complete_.load(std::memory_order_relaxed);
    auto last_sent = last_data_sent_.load(std::memory_order_relaxed);
    auto last_received = last_any_authenticated_.load(std::memory_order_relaxed);

    // Check for session expiry / need rekey
    auto session_age = now - last_complete;
    if (session_age >= TimerConstants::REJECT_AFTER_TIME) {
        return std::make_pair(TimerEvent::NewHandshake, Duration::zero());
    }

    // Check for keepalive
    // Send keepalive if we've received data but not sent anything back
    if (last_received > last_sent) {
        auto since_received = now - last_received;
        if (since_received >= TimerConstants::KEEPALIVE_TIMEOUT) {
            return std::make_pair(TimerEvent::SendKeepalive, Duration::zero());
        }

        auto until_keepalive = TimerConstants::KEEPALIVE_TIMEOUT - since_received;
        return std::make_pair(TimerEvent::SendKeepalive, until_keepalive);
    }

    // Check persistent keepalive
    if (persistent_keepalive_.count() > 0) {
        auto since_sent = now - last_sent;
        if (since_sent >= persistent_keepalive_) {
            return std::make_pair(TimerEvent::PersistentKeepalive, Duration::zero());
        }

        auto until_persistent = persistent_keepalive_ - std::chrono::duration_cast<std::chrono::seconds>(since_sent);
        return std::make_pair(TimerEvent::PersistentKeepalive, until_persistent);
    }

    // Check if we need to start a new handshake (approaching session expiry)
    if (session_age >= TimerConstants::REKEY_ATTEMPT_TIME) {
        return std::make_pair(TimerEvent::NewHandshake, Duration::zero());
    }

    return std::nullopt;
}

void PeerTimers::set_persistent_keepalive(std::chrono::seconds interval) {
    persistent_keepalive_ = interval;
}

void PeerTimers::reset() {
    auto min_time = TimePoint::min();
    last_handshake_initiation_.store(min_time, std::memory_order_relaxed);
    last_handshake_complete_.store(min_time, std::memory_order_relaxed);
    last_data_sent_.store(min_time, std::memory_order_relaxed);
    last_data_received_.store(min_time, std::memory_order_relaxed);
    last_any_authenticated_.store(min_time, std::memory_order_relaxed);
    handshake_attempts_.store(0, std::memory_order_relaxed);
    handshake_in_progress_.store(false, std::memory_order_relaxed);
    session_established_.store(false, std::memory_order_relaxed);
}

} // namespace vpn::protocol
