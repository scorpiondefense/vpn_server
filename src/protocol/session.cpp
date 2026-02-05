#include "vpn/protocol/session.hpp"

namespace vpn::protocol {

Session::Session(
    crypto::SymmetricKey send_key,
    crypto::SymmetricKey receive_key,
    uint32_t local_index,
    uint32_t remote_index
)
    : send_cipher_(send_key)
    , receive_cipher_(receive_key)
    , local_index_(local_index)
    , remote_index_(remote_index)
    , created_at_(std::chrono::steady_clock::now())
    , last_sent_at_(std::chrono::steady_clock::now())
    , last_received_at_(std::chrono::steady_clock::now())
{
}

uint64_t Session::next_send_counter() {
    return send_counter_.fetch_add(1, std::memory_order_relaxed);
}

uint64_t Session::current_send_counter() const {
    return send_counter_.load(std::memory_order_relaxed);
}

bool Session::update_replay_window(uint64_t counter) {
    // If counter is too old, reject
    if (counter + REPLAY_WINDOW_SIZE <= replay_counter_max_) {
        return false;
    }

    // If counter is new maximum, shift window
    if (counter > replay_counter_max_) {
        uint64_t shift = counter - replay_counter_max_;
        if (shift >= REPLAY_WINDOW_SIZE) {
            // Clear entire bitmap
            replay_bitmap_.fill(0);
        } else {
            // Shift bitmap
            size_t word_shift = static_cast<size_t>(shift / 64);
            size_t bit_shift = static_cast<size_t>(shift % 64);

            if (word_shift > 0) {
                for (size_t i = replay_bitmap_.size() - 1; i >= word_shift; --i) {
                    replay_bitmap_[i] = replay_bitmap_[i - word_shift];
                }
                for (size_t i = 0; i < word_shift; ++i) {
                    replay_bitmap_[i] = 0;
                }
            }

            if (bit_shift > 0) {
                for (size_t i = replay_bitmap_.size() - 1; i > 0; --i) {
                    replay_bitmap_[i] = (replay_bitmap_[i] << bit_shift) |
                                       (replay_bitmap_[i - 1] >> (64 - bit_shift));
                }
                replay_bitmap_[0] <<= bit_shift;
            }
        }
        replay_counter_max_ = counter;
    }

    // Check and set bit for this counter
    uint64_t offset = replay_counter_max_ - counter;
    size_t word_index = static_cast<size_t>(offset / 64);
    size_t bit_index = static_cast<size_t>(offset % 64);

    if (word_index >= replay_bitmap_.size()) {
        return false;  // Should not happen given earlier check
    }

    uint64_t mask = 1ULL << bit_index;
    if (replay_bitmap_[word_index] & mask) {
        return false;  // Already seen
    }

    replay_bitmap_[word_index] |= mask;
    return true;
}

bool Session::is_valid_receive_counter(uint64_t counter) {
    std::lock_guard lock(replay_mutex_);
    return update_replay_window(counter);
}

std::vector<uint8_t> Session::encrypt(std::span<const uint8_t> plaintext) {
    uint64_t counter = next_send_counter();
    update_last_sent();
    return send_cipher_.encrypt(plaintext, {}, counter);
}

std::optional<std::vector<uint8_t>> Session::decrypt(
    std::span<const uint8_t> ciphertext,
    uint64_t counter
) {
    // Check replay protection first
    if (!is_valid_receive_counter(counter)) {
        return std::nullopt;
    }

    auto result = receive_cipher_.decrypt(ciphertext, {}, counter);
    if (result) {
        update_last_received();
    }
    return result;
}

bool Session::needs_rekey() const {
    auto age = std::chrono::steady_clock::now() - created_at_;
    if (age >= REKEY_AFTER_TIME) {
        return true;
    }

    // Note: REKEY_AFTER_MESSAGES is 2^60 - 16, practically never reached
    // but we check anyway for correctness
    if (current_send_counter() >= REKEY_AFTER_MESSAGES) {
        return true;
    }

    return false;
}

bool Session::is_expired() const {
    auto age = std::chrono::steady_clock::now() - created_at_;
    if (age >= REJECT_AFTER_TIME) {
        return true;
    }

    if (current_send_counter() >= REJECT_AFTER_MESSAGES) {
        return true;
    }

    return false;
}

std::chrono::steady_clock::time_point Session::last_sent_at() const {
    return last_sent_at_.load(std::memory_order_relaxed);
}

std::chrono::steady_clock::time_point Session::last_received_at() const {
    return last_received_at_.load(std::memory_order_relaxed);
}

void Session::update_last_sent() {
    last_sent_at_.store(std::chrono::steady_clock::now(), std::memory_order_relaxed);
}

void Session::update_last_received() {
    last_received_at_.store(std::chrono::steady_clock::now(), std::memory_order_relaxed);
}

} // namespace vpn::protocol
