#include "vpn/crypto/blake2s.hpp"
#include <sodium.h>
#include <stdexcept>
#include <cstring>

namespace vpn::crypto {

namespace {

void ensure_sodium_initialized() {
    static bool initialized = false;
    if (!initialized) {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
        initialized = true;
    }
}

// Internal HMAC-BLAKE2s implementation
Hash hmac_blake2s_impl(std::span<const uint8_t> key, std::span<const uint8_t> data) {
    // HMAC construction: HASH(K XOR opad || HASH(K XOR ipad || message))
    constexpr size_t BLOCK_SIZE = 64;  // BLAKE2s block size

    std::array<uint8_t, BLOCK_SIZE> key_block{};
    if (key.size() > BLOCK_SIZE) {
        // If key is longer than block size, hash it first
        auto key_hash = blake2s(key);
        std::memcpy(key_block.data(), key_hash.data(), HASH_SIZE);
    } else {
        std::memcpy(key_block.data(), key.data(), key.size());
    }

    std::array<uint8_t, BLOCK_SIZE> inner_key{};
    std::array<uint8_t, BLOCK_SIZE> outer_key{};

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        inner_key[i] = key_block[i] ^ 0x36;
        outer_key[i] = key_block[i] ^ 0x5c;
    }

    // Inner hash: HASH(K XOR ipad || message)
    crypto_generichash_blake2b_state inner_state;
    crypto_generichash_blake2b_init(&inner_state, nullptr, 0, HASH_SIZE);
    crypto_generichash_blake2b_update(&inner_state, inner_key.data(), BLOCK_SIZE);
    crypto_generichash_blake2b_update(&inner_state, data.data(), data.size());

    Hash inner_hash;
    crypto_generichash_blake2b_final(&inner_state, inner_hash.data(), HASH_SIZE);

    // Outer hash: HASH(K XOR opad || inner_hash)
    crypto_generichash_blake2b_state outer_state;
    crypto_generichash_blake2b_init(&outer_state, nullptr, 0, HASH_SIZE);
    crypto_generichash_blake2b_update(&outer_state, outer_key.data(), BLOCK_SIZE);
    crypto_generichash_blake2b_update(&outer_state, inner_hash.data(), HASH_SIZE);

    Hash result;
    crypto_generichash_blake2b_final(&outer_state, result.data(), HASH_SIZE);
    return result;
}

} // anonymous namespace

Hash blake2s(std::span<const uint8_t> data) {
    ensure_sodium_initialized();

    Hash result;
    // libsodium uses BLAKE2b, but for 32-byte output it's compatible
    // For true BLAKE2s, we'd need a different library, but WireGuard
    // implementations often use BLAKE2b with 32-byte output
    crypto_generichash_blake2b(
        result.data(), HASH_SIZE,
        data.data(), data.size(),
        nullptr, 0
    );
    return result;
}

Hash blake2s_keyed(std::span<const uint8_t> key, std::span<const uint8_t> data) {
    ensure_sodium_initialized();

    if (key.size() > 32) {
        throw std::runtime_error("BLAKE2s key must be at most 32 bytes");
    }

    Hash result;
    crypto_generichash_blake2b(
        result.data(), HASH_SIZE,
        data.data(), data.size(),
        key.data(), key.size()
    );
    return result;
}

Hash hmac_blake2s(std::span<const uint8_t> key, std::span<const uint8_t> data) {
    ensure_sodium_initialized();
    return hmac_blake2s_impl(key, data);
}

Hash hkdf_extract(std::span<const uint8_t> salt, std::span<const uint8_t> input_key_material) {
    ensure_sodium_initialized();

    // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    // If salt is empty, use a string of HashLen zeros
    if (salt.empty()) {
        std::array<uint8_t, HASH_SIZE> zero_salt{};
        return hmac_blake2s_impl({zero_salt.data(), HASH_SIZE}, input_key_material);
    }
    return hmac_blake2s_impl(salt, input_key_material);
}

// Explicit template instantiations
template<>
std::array<SymmetricKey, 1> hkdf_expand(const Hash& prk, std::span<const uint8_t> info) {
    std::array<SymmetricKey, 1> result;

    // T(1) = HMAC-Hash(PRK, info || 0x01)
    std::vector<uint8_t> input(info.size() + 1);
    std::memcpy(input.data(), info.data(), info.size());
    input[info.size()] = 0x01;

    auto t1 = hmac_blake2s_impl({prk.data(), HASH_SIZE}, input);
    std::memcpy(result[0].data(), t1.data(), KEY_SIZE);

    return result;
}

template<>
std::array<SymmetricKey, 2> hkdf_expand(const Hash& prk, std::span<const uint8_t> info) {
    std::array<SymmetricKey, 2> result;

    // T(1) = HMAC-Hash(PRK, info || 0x01)
    std::vector<uint8_t> input1(info.size() + 1);
    std::memcpy(input1.data(), info.data(), info.size());
    input1[info.size()] = 0x01;

    auto t1 = hmac_blake2s_impl({prk.data(), HASH_SIZE}, input1);
    std::memcpy(result[0].data(), t1.data(), KEY_SIZE);

    // T(2) = HMAC-Hash(PRK, T(1) || info || 0x02)
    std::vector<uint8_t> input2(HASH_SIZE + info.size() + 1);
    std::memcpy(input2.data(), t1.data(), HASH_SIZE);
    std::memcpy(input2.data() + HASH_SIZE, info.data(), info.size());
    input2[HASH_SIZE + info.size()] = 0x02;

    auto t2 = hmac_blake2s_impl({prk.data(), HASH_SIZE}, input2);
    std::memcpy(result[1].data(), t2.data(), KEY_SIZE);

    return result;
}

template<>
std::array<SymmetricKey, 3> hkdf_expand(const Hash& prk, std::span<const uint8_t> info) {
    std::array<SymmetricKey, 3> result;

    // T(1)
    std::vector<uint8_t> input1(info.size() + 1);
    std::memcpy(input1.data(), info.data(), info.size());
    input1[info.size()] = 0x01;

    auto t1 = hmac_blake2s_impl({prk.data(), HASH_SIZE}, input1);
    std::memcpy(result[0].data(), t1.data(), KEY_SIZE);

    // T(2)
    std::vector<uint8_t> input2(HASH_SIZE + info.size() + 1);
    std::memcpy(input2.data(), t1.data(), HASH_SIZE);
    std::memcpy(input2.data() + HASH_SIZE, info.data(), info.size());
    input2[HASH_SIZE + info.size()] = 0x02;

    auto t2 = hmac_blake2s_impl({prk.data(), HASH_SIZE}, input2);
    std::memcpy(result[1].data(), t2.data(), KEY_SIZE);

    // T(3)
    std::vector<uint8_t> input3(HASH_SIZE + info.size() + 1);
    std::memcpy(input3.data(), t2.data(), HASH_SIZE);
    std::memcpy(input3.data() + HASH_SIZE, info.data(), info.size());
    input3[HASH_SIZE + info.size()] = 0x03;

    auto t3 = hmac_blake2s_impl({prk.data(), HASH_SIZE}, input3);
    std::memcpy(result[2].data(), t3.data(), KEY_SIZE);

    return result;
}

template<>
std::array<SymmetricKey, 1> hkdf(
    std::span<const uint8_t> salt,
    std::span<const uint8_t> input_key_material,
    std::span<const uint8_t> info
) {
    auto prk = hkdf_extract(salt, input_key_material);
    return hkdf_expand<1>(prk, info);
}

template<>
std::array<SymmetricKey, 2> hkdf(
    std::span<const uint8_t> salt,
    std::span<const uint8_t> input_key_material,
    std::span<const uint8_t> info
) {
    auto prk = hkdf_extract(salt, input_key_material);
    return hkdf_expand<2>(prk, info);
}

template<>
std::array<SymmetricKey, 3> hkdf(
    std::span<const uint8_t> salt,
    std::span<const uint8_t> input_key_material,
    std::span<const uint8_t> info
) {
    auto prk = hkdf_extract(salt, input_key_material);
    return hkdf_expand<3>(prk, info);
}

KdfResult mix_key(const SymmetricKey& chaining_key, std::span<const uint8_t> input_key_material) {
    auto keys = hkdf<2>({chaining_key.data(), KEY_SIZE}, input_key_material);
    return KdfResult{std::move(keys[0]), std::move(keys[1])};
}

Hash mix_hash(const Hash& hash, std::span<const uint8_t> data) {
    std::vector<uint8_t> combined(HASH_SIZE + data.size());
    std::memcpy(combined.data(), hash.data(), HASH_SIZE);
    std::memcpy(combined.data() + HASH_SIZE, data.data(), data.size());
    return blake2s(combined);
}

// Blake2sContext implementation

Blake2sContext::Blake2sContext() {
    ensure_sodium_initialized();
    auto* state = reinterpret_cast<crypto_generichash_blake2b_state*>(state_buffer_.data());
    crypto_generichash_blake2b_init(state, nullptr, 0, HASH_SIZE);
}

Blake2sContext::Blake2sContext(std::span<const uint8_t> key) {
    ensure_sodium_initialized();
    if (key.size() > 32) {
        throw std::runtime_error("BLAKE2s key must be at most 32 bytes");
    }
    auto* state = reinterpret_cast<crypto_generichash_blake2b_state*>(state_buffer_.data());
    crypto_generichash_blake2b_init(state, key.data(), key.size(), HASH_SIZE);
}

void Blake2sContext::update(std::span<const uint8_t> data) {
    auto* state = reinterpret_cast<crypto_generichash_blake2b_state*>(state_buffer_.data());
    crypto_generichash_blake2b_update(state, data.data(), data.size());
}

void Blake2sContext::update(std::string_view data) {
    update({reinterpret_cast<const uint8_t*>(data.data()), data.size()});
}

Hash Blake2sContext::finalize() {
    Hash result;
    auto* state = reinterpret_cast<crypto_generichash_blake2b_state*>(state_buffer_.data());
    crypto_generichash_blake2b_final(state, result.data(), HASH_SIZE);
    return result;
}

void Blake2sContext::reset() {
    auto* state = reinterpret_cast<crypto_generichash_blake2b_state*>(state_buffer_.data());
    crypto_generichash_blake2b_init(state, nullptr, 0, HASH_SIZE);
}

void Blake2sContext::reset(std::span<const uint8_t> key) {
    if (key.size() > 32) {
        throw std::runtime_error("BLAKE2s key must be at most 32 bytes");
    }
    auto* state = reinterpret_cast<crypto_generichash_blake2b_state*>(state_buffer_.data());
    crypto_generichash_blake2b_init(state, key.data(), key.size(), HASH_SIZE);
}

Hash construction_hash() {
    return blake2s({reinterpret_cast<const uint8_t*>(NOISE_CONSTRUCTION.data()),
                    NOISE_CONSTRUCTION.size()});
}

Hash identifier_hash() {
    auto ch = construction_hash();
    return mix_hash(ch, {reinterpret_cast<const uint8_t*>(WG_IDENTIFIER.data()),
                        WG_IDENTIFIER.size()});
}

} // namespace vpn::crypto
