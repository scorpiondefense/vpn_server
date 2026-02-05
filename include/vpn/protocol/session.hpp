#pragma once

#include "vpn/crypto/types.hpp"
#include "vpn/crypto/chacha20poly1305.hpp"
#include <atomic>
#include <chrono>
#include <mutex>
#include <memory>

namespace vpn::protocol {

// A session represents an established cryptographic session with a peer
class Session {
public:
    Session(
        crypto::SymmetricKey send_key,
        crypto::SymmetricKey receive_key,
        uint32_t local_index,
        uint32_t remote_index
    );

    // Get session indices
    uint32_t local_index() const { return local_index_; }
    uint32_t remote_index() const { return remote_index_; }

    // Get and increment send counter (thread-safe)
    uint64_t next_send_counter();

    // Get current send counter without incrementing
    uint64_t current_send_counter() const;

    // Check if a receive counter is valid (replay protection)
    bool is_valid_receive_counter(uint64_t counter);

    // Encrypt data for sending
    // Returns ciphertext including 16-byte tag
    std::vector<uint8_t> encrypt(std::span<const uint8_t> plaintext);

    // Decrypt received data
    // Returns plaintext or nullopt if decryption fails
    std::optional<std::vector<uint8_t>> decrypt(
        std::span<const uint8_t> ciphertext,
        uint64_t counter
    );

    // Check if session needs rekeying
    bool needs_rekey() const;

    // Check if session is expired
    bool is_expired() const;

    // Get creation time
    std::chrono::steady_clock::time_point created_at() const { return created_at_; }

    // Get last data sent time
    std::chrono::steady_clock::time_point last_sent_at() const;

    // Get last data received time
    std::chrono::steady_clock::time_point last_received_at() const;

    // Update last sent time
    void update_last_sent();

    // Update last received time
    void update_last_received();

    // WireGuard timing constants
    static constexpr auto REKEY_AFTER_TIME = std::chrono::seconds(120);
    static constexpr auto REJECT_AFTER_TIME = std::chrono::seconds(180);
    static constexpr uint64_t REKEY_AFTER_MESSAGES = (1ULL << 60) - (1ULL << 4);
    static constexpr uint64_t REJECT_AFTER_MESSAGES = UINT64_MAX - (1ULL << 13);

private:
    // Replay window for receive counter
    static constexpr size_t REPLAY_WINDOW_SIZE = 8192;

    bool update_replay_window(uint64_t counter);

    crypto::ChaCha20Poly1305 send_cipher_;
    crypto::ChaCha20Poly1305 receive_cipher_;

    uint32_t local_index_;
    uint32_t remote_index_;

    std::atomic<uint64_t> send_counter_{0};

    // Replay protection
    mutable std::mutex replay_mutex_;
    uint64_t replay_counter_max_ = 0;
    std::array<uint64_t, REPLAY_WINDOW_SIZE / 64> replay_bitmap_{};

    // Timestamps
    std::chrono::steady_clock::time_point created_at_;
    std::atomic<std::chrono::steady_clock::time_point> last_sent_at_;
    std::atomic<std::chrono::steady_clock::time_point> last_received_at_;
};

} // namespace vpn::protocol
