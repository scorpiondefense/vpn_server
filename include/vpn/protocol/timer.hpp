#pragma once

#include <chrono>
#include <functional>
#include <atomic>
#include <optional>

namespace vpn::protocol {

// Timer events for WireGuard protocol
enum class TimerEvent {
    RetransmitHandshake,
    SendKeepalive,
    NewHandshake,
    ZeroKeys,
    PersistentKeepalive
};

// Timer durations (WireGuard spec)
struct TimerConstants {
    static constexpr auto REKEY_TIMEOUT = std::chrono::seconds(5);
    static constexpr auto REKEY_ATTEMPT_TIME = std::chrono::seconds(90);
    static constexpr auto KEEPALIVE_TIMEOUT = std::chrono::seconds(10);
    static constexpr auto REJECT_AFTER_TIME = std::chrono::seconds(180);
    static constexpr auto MAX_TIMER_HANDSHAKES = 20;
};

// Per-peer timer state
class PeerTimers {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    using Duration = Clock::duration;

    PeerTimers();

    // Record that we sent a handshake initiation
    void handshake_initiated();

    // Record that handshake completed
    void handshake_complete();

    // Record that we sent data
    void data_sent();

    // Record that we received data
    void data_received();

    // Record that we received an authenticated packet
    void any_authenticated_packet_received();

    // Check which timer event should fire (if any)
    // Returns the event and time until it fires (0 if should fire now)
    std::optional<std::pair<TimerEvent, Duration>> next_event() const;

    // Set persistent keepalive interval (0 to disable)
    void set_persistent_keepalive(std::chrono::seconds interval);

    // Get handshake attempt count
    int handshake_attempts() const { return handshake_attempts_; }

    // Reset all timers
    void reset();

    // Check if handshake is in progress
    bool handshake_in_progress() const { return handshake_in_progress_; }

private:
    std::atomic<TimePoint> last_handshake_initiation_{TimePoint::min()};
    std::atomic<TimePoint> last_handshake_complete_{TimePoint::min()};
    std::atomic<TimePoint> last_data_sent_{TimePoint::min()};
    std::atomic<TimePoint> last_data_received_{TimePoint::min()};
    std::atomic<TimePoint> last_any_authenticated_{TimePoint::min()};

    std::atomic<int> handshake_attempts_{0};
    std::atomic<bool> handshake_in_progress_{false};
    std::atomic<bool> session_established_{false};

    std::chrono::seconds persistent_keepalive_{0};
};

} // namespace vpn::protocol
