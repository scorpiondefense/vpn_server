#pragma once

#include "types.hpp"
#include <string_view>

namespace vpn::crypto {

// BLAKE2s hash function as used by WireGuard
// Provides hashing, keyed hashing (MAC), and HKDF functionality

// Simple hash function
Hash blake2s(std::span<const uint8_t> data);

// Hash with custom output size
template<size_t N>
SecureArray<N> blake2s_sized(std::span<const uint8_t> data);

// Keyed hash (MAC)
Hash blake2s_keyed(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data
);

// HMAC-BLAKE2s for HKDF
Hash hmac_blake2s(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data
);

// HKDF-Extract (BLAKE2s based)
// Extracts a pseudorandom key from input keying material
Hash hkdf_extract(
    std::span<const uint8_t> salt,
    std::span<const uint8_t> input_key_material
);

// HKDF-Expand (BLAKE2s based)
// Expands a pseudorandom key into output keying material
// Returns N output keys of KEY_SIZE each
template<size_t N>
std::array<SymmetricKey, N> hkdf_expand(
    const Hash& prk,
    std::span<const uint8_t> info = {}
);

// Combined HKDF (extract + expand)
template<size_t N>
std::array<SymmetricKey, N> hkdf(
    std::span<const uint8_t> salt,
    std::span<const uint8_t> input_key_material,
    std::span<const uint8_t> info = {}
);

// WireGuard-specific KDF using BLAKE2s
// MixKey: derives new chaining key and output key
struct KdfResult {
    SymmetricKey chaining_key;
    SymmetricKey output_key;
};

KdfResult mix_key(
    const SymmetricKey& chaining_key,
    std::span<const uint8_t> input_key_material
);

// MixHash: mixes data into the hash
Hash mix_hash(const Hash& hash, std::span<const uint8_t> data);

// Incremental hashing context
class Blake2sContext {
public:
    Blake2sContext();
    explicit Blake2sContext(std::span<const uint8_t> key);

    void update(std::span<const uint8_t> data);
    void update(std::string_view data);

    Hash finalize();

    void reset();
    void reset(std::span<const uint8_t> key);

private:
    struct State;
    alignas(std::max_align_t) std::array<uint8_t, 384> state_buffer_;  // Properly aligned for crypto_generichash_blake2b_state
};

// Construction identifier for WireGuard Noise protocol
inline constexpr std::string_view NOISE_CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
inline constexpr std::string_view WG_IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com";
inline constexpr std::string_view WG_LABEL_MAC1 = "mac1----";
inline constexpr std::string_view WG_LABEL_COOKIE = "cookie--";

// Pre-computed protocol hashes
Hash construction_hash();
Hash identifier_hash();

} // namespace vpn::crypto
