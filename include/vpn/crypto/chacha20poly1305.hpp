#pragma once

#include "types.hpp"
#include <optional>
#include <vector>

namespace vpn::crypto {

// ChaCha20-Poly1305 AEAD cipher as specified in RFC 7539
// Used by WireGuard for all symmetric encryption
class ChaCha20Poly1305 {
public:
    explicit ChaCha20Poly1305(const SymmetricKey& key);

    // Encrypt plaintext with associated data
    // Returns ciphertext with appended authentication tag
    std::vector<uint8_t> encrypt(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> additional_data,
        Counter counter
    ) const;

    // Encrypt in-place (buffer must have TAG_SIZE extra bytes)
    // Returns size of ciphertext including tag
    size_t encrypt_in_place(
        std::span<uint8_t> buffer,
        size_t plaintext_len,
        std::span<const uint8_t> additional_data,
        Counter counter
    ) const;

    // Decrypt ciphertext with associated data
    // Returns plaintext or nullopt if authentication fails
    std::optional<std::vector<uint8_t>> decrypt(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> additional_data,
        Counter counter
    ) const;

    // Decrypt in-place
    // Returns plaintext size or nullopt if authentication fails
    std::optional<size_t> decrypt_in_place(
        std::span<uint8_t> buffer,
        size_t ciphertext_len,
        std::span<const uint8_t> additional_data,
        Counter counter
    ) const;

    // Get the overhead added by encryption (tag size)
    static constexpr size_t overhead() { return TAG_SIZE; }

private:
    // Construct nonce from counter (WireGuard format: 4 zero bytes + 8-byte LE counter)
    static Nonce make_nonce(Counter counter);

    SymmetricKey key_;
};

// XChaCha20-Poly1305 variant with extended nonce (used in some contexts)
class XChaCha20Poly1305 {
public:
    static constexpr size_t NONCE_SIZE = 24;

    explicit XChaCha20Poly1305(const SymmetricKey& key);

    std::vector<uint8_t> encrypt(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> additional_data,
        std::span<const uint8_t, NONCE_SIZE> nonce
    ) const;

    std::optional<std::vector<uint8_t>> decrypt(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> additional_data,
        std::span<const uint8_t, NONCE_SIZE> nonce
    ) const;

private:
    SymmetricKey key_;
};

} // namespace vpn::crypto
