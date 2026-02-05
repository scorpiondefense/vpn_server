#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>
#include <cstring>

namespace vpn::crypto {

// WireGuard key sizes
inline constexpr size_t KEY_SIZE = 32;
inline constexpr size_t NONCE_SIZE = 12;  // ChaCha20-Poly1305 nonce
inline constexpr size_t TAG_SIZE = 16;    // Poly1305 tag
inline constexpr size_t HASH_SIZE = 32;   // BLAKE2s output

// Key types with secure memory handling
template<size_t N>
class SecureArray {
public:
    SecureArray() { std::memset(data_.data(), 0, N); }

    ~SecureArray() { clear(); }

    SecureArray(const SecureArray& other) {
        std::memcpy(data_.data(), other.data_.data(), N);
    }

    SecureArray& operator=(const SecureArray& other) {
        if (this != &other) {
            std::memcpy(data_.data(), other.data_.data(), N);
        }
        return *this;
    }

    SecureArray(SecureArray&& other) noexcept {
        std::memcpy(data_.data(), other.data_.data(), N);
        other.clear();
    }

    SecureArray& operator=(SecureArray&& other) noexcept {
        if (this != &other) {
            std::memcpy(data_.data(), other.data_.data(), N);
            other.clear();
        }
        return *this;
    }

    void clear() {
        // Volatile to prevent compiler optimization
        volatile uint8_t* p = data_.data();
        for (size_t i = 0; i < N; ++i) {
            p[i] = 0;
        }
    }

    uint8_t* data() { return data_.data(); }
    const uint8_t* data() const { return data_.data(); }

    static constexpr size_t size() { return N; }

    uint8_t& operator[](size_t i) { return data_[i]; }
    const uint8_t& operator[](size_t i) const { return data_[i]; }

    std::span<uint8_t> span() { return {data_.data(), N}; }
    std::span<const uint8_t> span() const { return {data_.data(), N}; }

    bool operator==(const SecureArray& other) const {
        return std::memcmp(data_.data(), other.data_.data(), N) == 0;
    }

    bool operator!=(const SecureArray& other) const {
        return !(*this == other);
    }

private:
    std::array<uint8_t, N> data_;
};

using PrivateKey = SecureArray<KEY_SIZE>;
using PublicKey = SecureArray<KEY_SIZE>;
using SharedSecret = SecureArray<KEY_SIZE>;
using SymmetricKey = SecureArray<KEY_SIZE>;
using Hash = SecureArray<HASH_SIZE>;
using Nonce = std::array<uint8_t, NONCE_SIZE>;

// Pre-shared key (optional in WireGuard)
using PresharedKey = SecureArray<KEY_SIZE>;

// Counter for ChaCha20-Poly1305 nonce construction
using Counter = uint64_t;

} // namespace vpn::crypto
