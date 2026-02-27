#include "vpn/crypto/blake2s.hpp"
#include "vpn/util/logger.hpp"
#include <sodium.h>
#include <stdexcept>
#include <cstring>
#include <array>
#include <sstream>
#include <iomanip>

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

// ============================================================================
// True BLAKE2s implementation (RFC 7693)
// BLAKE2b and BLAKE2s are NOT interchangeable — they use different word sizes,
// IVs, sigma schedules, and rotation constants.
// ============================================================================

// BLAKE2s uses 32-bit words
using word_t = uint32_t;

constexpr size_t BLAKE2S_BLOCKBYTES = 64;
constexpr size_t BLAKE2S_OUTBYTES = 32;
constexpr size_t BLAKE2S_KEYBYTES = 32;

// IV for BLAKE2s (first 32 bits of fractional parts of sqrt of first 8 primes)
static constexpr word_t blake2s_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

// Sigma schedule for BLAKE2s (same as BLAKE2b)
static constexpr uint8_t blake2s_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
};

inline word_t rotr32(word_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

inline void G(word_t v[16], int a, int b, int c, int d, word_t x, word_t y) {
    v[a] = v[a] + v[b] + x;
    v[d] = rotr32(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = rotr32(v[b] ^ v[c], 12);
    v[a] = v[a] + v[b] + y;
    v[d] = rotr32(v[d] ^ v[a], 8);
    v[c] = v[c] + v[d];
    v[b] = rotr32(v[b] ^ v[c], 7);
}

struct Blake2sState {
    word_t h[8];           // chained state
    word_t t[2];           // total bytes counter
    word_t f[2];           // finalization flags
    uint8_t buf[BLAKE2S_BLOCKBYTES];
    size_t buflen;
    size_t outlen;
};

inline word_t load32_le(const void* src) {
    const uint8_t* p = static_cast<const uint8_t*>(src);
    return static_cast<word_t>(p[0])
        | (static_cast<word_t>(p[1]) << 8)
        | (static_cast<word_t>(p[2]) << 16)
        | (static_cast<word_t>(p[3]) << 24);
}

inline void store32_le(void* dst, word_t w) {
    auto* p = static_cast<uint8_t*>(dst);
    p[0] = static_cast<uint8_t>(w);
    p[1] = static_cast<uint8_t>(w >> 8);
    p[2] = static_cast<uint8_t>(w >> 16);
    p[3] = static_cast<uint8_t>(w >> 24);
}

void blake2s_compress(Blake2sState& S, const uint8_t block[BLAKE2S_BLOCKBYTES]) {
    word_t m[16];
    word_t v[16];

    for (size_t i = 0; i < 16; ++i) {
        m[i] = load32_le(block + i * 4);
    }

    for (size_t i = 0; i < 8; ++i) {
        v[i] = S.h[i];
    }
    v[8]  = blake2s_IV[0];
    v[9]  = blake2s_IV[1];
    v[10] = blake2s_IV[2];
    v[11] = blake2s_IV[3];
    v[12] = S.t[0] ^ blake2s_IV[4];
    v[13] = S.t[1] ^ blake2s_IV[5];
    v[14] = S.f[0] ^ blake2s_IV[6];
    v[15] = S.f[1] ^ blake2s_IV[7];

    for (size_t i = 0; i < 10; ++i) {
        G(v, 0, 4,  8, 12, m[blake2s_sigma[i][ 0]], m[blake2s_sigma[i][ 1]]);
        G(v, 1, 5,  9, 13, m[blake2s_sigma[i][ 2]], m[blake2s_sigma[i][ 3]]);
        G(v, 2, 6, 10, 14, m[blake2s_sigma[i][ 4]], m[blake2s_sigma[i][ 5]]);
        G(v, 3, 7, 11, 15, m[blake2s_sigma[i][ 6]], m[blake2s_sigma[i][ 7]]);
        G(v, 0, 5, 10, 15, m[blake2s_sigma[i][ 8]], m[blake2s_sigma[i][ 9]]);
        G(v, 1, 6, 11, 12, m[blake2s_sigma[i][10]], m[blake2s_sigma[i][11]]);
        G(v, 2, 7,  8, 13, m[blake2s_sigma[i][12]], m[blake2s_sigma[i][13]]);
        G(v, 3, 4,  9, 14, m[blake2s_sigma[i][14]], m[blake2s_sigma[i][15]]);
    }

    for (size_t i = 0; i < 8; ++i) {
        S.h[i] ^= v[i] ^ v[i + 8];
    }
}

void blake2s_increment_counter(Blake2sState& S, word_t inc) {
    S.t[0] += inc;
    S.t[1] += (S.t[0] < inc) ? 1 : 0;
}

void blake2s_init(Blake2sState& S, size_t outlen, const uint8_t* key, size_t keylen) {
    std::memset(&S, 0, sizeof(S));
    S.outlen = outlen;

    for (size_t i = 0; i < 8; ++i) {
        S.h[i] = blake2s_IV[i];
    }

    // Parameter block: digest_length | key_length | fanout=1 | depth=1
    S.h[0] ^= 0x01010000 ^ (static_cast<word_t>(keylen) << 8) ^ static_cast<word_t>(outlen);

    if (keylen > 0 && key != nullptr) {
        uint8_t block[BLAKE2S_BLOCKBYTES] = {};
        std::memcpy(block, key, keylen);
        blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);
        blake2s_compress(S, block);
        S.buflen = 0;
        sodium_memzero(block, BLAKE2S_BLOCKBYTES);
    }
}

void blake2s_update(Blake2sState& S, const uint8_t* in, size_t inlen) {
    if (inlen == 0) return;

    // If buffer has data and adding new data would overflow, compress
    if (S.buflen > 0) {
        size_t left = S.buflen;
        size_t fill = BLAKE2S_BLOCKBYTES - left;
        if (inlen > fill) {
            std::memcpy(S.buf + left, in, fill);
            blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);
            blake2s_compress(S, S.buf);
            S.buflen = 0;
            in += fill;
            inlen -= fill;
        } else {
            std::memcpy(S.buf + left, in, inlen);
            S.buflen += inlen;
            return;
        }
    }

    // Compress full blocks (keep at least 1 byte for finalization)
    while (inlen > BLAKE2S_BLOCKBYTES) {
        blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);
        blake2s_compress(S, in);
        in += BLAKE2S_BLOCKBYTES;
        inlen -= BLAKE2S_BLOCKBYTES;
    }

    // Buffer remaining
    std::memcpy(S.buf + S.buflen, in, inlen);
    S.buflen += inlen;
}

void blake2s_final(Blake2sState& S, uint8_t* out, size_t outlen) {
    // Pad and compress last block
    blake2s_increment_counter(S, static_cast<word_t>(S.buflen));
    S.f[0] = ~static_cast<word_t>(0);  // Set finalization flag
    std::memset(S.buf + S.buflen, 0, BLAKE2S_BLOCKBYTES - S.buflen);
    blake2s_compress(S, S.buf);

    // Output
    uint8_t buffer[BLAKE2S_OUTBYTES];
    for (size_t i = 0; i < 8; ++i) {
        store32_le(buffer + i * 4, S.h[i]);
    }
    std::memcpy(out, buffer, outlen);
}

// Convenience: one-shot BLAKE2s hash
void blake2s_hash(uint8_t* out, size_t outlen,
                  const uint8_t* in, size_t inlen,
                  const uint8_t* key, size_t keylen) {
    Blake2sState S;
    blake2s_init(S, outlen, key, keylen);
    blake2s_update(S, in, inlen);
    blake2s_final(S, out, outlen);
}

// HMAC-BLAKE2s using true BLAKE2s
Hash hmac_blake2s_impl(std::span<const uint8_t> key, std::span<const uint8_t> data) {
    constexpr size_t BLOCK_SIZE = 64;  // BLAKE2s block size

    std::array<uint8_t, BLOCK_SIZE> key_block{};
    if (key.size() > BLOCK_SIZE) {
        blake2s_hash(key_block.data(), HASH_SIZE, key.data(), key.size(), nullptr, 0);
    } else {
        std::memcpy(key_block.data(), key.data(), key.size());
    }

    std::array<uint8_t, BLOCK_SIZE> inner_key{};
    std::array<uint8_t, BLOCK_SIZE> outer_key{};
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        inner_key[i] = key_block[i] ^ 0x36;
        outer_key[i] = key_block[i] ^ 0x5c;
    }

    // Inner hash: BLAKE2s(K XOR ipad || message)
    Blake2sState inner_state;
    blake2s_init(inner_state, HASH_SIZE, nullptr, 0);
    blake2s_update(inner_state, inner_key.data(), BLOCK_SIZE);
    blake2s_update(inner_state, data.data(), data.size());
    Hash inner_hash;
    blake2s_final(inner_state, inner_hash.data(), HASH_SIZE);

    // Outer hash: BLAKE2s(K XOR opad || inner_hash)
    Blake2sState outer_state;
    blake2s_init(outer_state, HASH_SIZE, nullptr, 0);
    blake2s_update(outer_state, outer_key.data(), BLOCK_SIZE);
    blake2s_update(outer_state, inner_hash.data(), HASH_SIZE);
    Hash result;
    blake2s_final(outer_state, result.data(), HASH_SIZE);

    return result;
}

} // anonymous namespace

Hash blake2s(std::span<const uint8_t> data) {
    ensure_sodium_initialized();

    Hash result;
    blake2s_hash(result.data(), HASH_SIZE, data.data(), data.size(), nullptr, 0);
    return result;
}

Hash blake2s_keyed(std::span<const uint8_t> key, std::span<const uint8_t> data) {
    ensure_sodium_initialized();

    if (key.size() > BLAKE2S_KEYBYTES) {
        throw std::runtime_error("BLAKE2s key must be at most 32 bytes");
    }

    Hash result;
    blake2s_hash(result.data(), HASH_SIZE, data.data(), data.size(), key.data(), key.size());
    return result;
}

std::array<uint8_t, 16> blake2s_mac(std::span<const uint8_t> key, std::span<const uint8_t> data) {
    ensure_sodium_initialized();

    if (key.size() > BLAKE2S_KEYBYTES) {
        throw std::runtime_error("BLAKE2s key must be at most 32 bytes");
    }

    // WireGuard Mac(key, input) := BLAKE2s(input, key, 16)
    // digest_size=16 — the output length is part of the parameter block,
    // so this is NOT the same as blake2s_keyed(...) truncated to 16 bytes!
    std::array<uint8_t, 16> result;
    blake2s_hash(result.data(), 16, data.data(), data.size(), key.data(), key.size());
    return result;
}

Hash hmac_blake2s(std::span<const uint8_t> key, std::span<const uint8_t> data) {
    ensure_sodium_initialized();
    return hmac_blake2s_impl(key, data);
}

Hash hkdf_extract(std::span<const uint8_t> salt, std::span<const uint8_t> input_key_material) {
    ensure_sodium_initialized();

    // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
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

    std::vector<uint8_t> input1(info.size() + 1);
    std::memcpy(input1.data(), info.data(), info.size());
    input1[info.size()] = 0x01;

    auto t1 = hmac_blake2s_impl({prk.data(), HASH_SIZE}, input1);
    std::memcpy(result[0].data(), t1.data(), KEY_SIZE);

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

    std::vector<uint8_t> input1(info.size() + 1);
    std::memcpy(input1.data(), info.data(), info.size());
    input1[info.size()] = 0x01;

    auto t1 = hmac_blake2s_impl({prk.data(), HASH_SIZE}, input1);
    std::memcpy(result[0].data(), t1.data(), KEY_SIZE);

    std::vector<uint8_t> input2(HASH_SIZE + info.size() + 1);
    std::memcpy(input2.data(), t1.data(), HASH_SIZE);
    std::memcpy(input2.data() + HASH_SIZE, info.data(), info.size());
    input2[HASH_SIZE + info.size()] = 0x02;

    auto t2 = hmac_blake2s_impl({prk.data(), HASH_SIZE}, input2);
    std::memcpy(result[1].data(), t2.data(), KEY_SIZE);

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

// Blake2sContext implementation — now uses true BLAKE2s

Blake2sContext::Blake2sContext() {
    ensure_sodium_initialized();
    static_assert(sizeof(Blake2sState) <= sizeof(state_buffer_));
    auto* state = reinterpret_cast<Blake2sState*>(state_buffer_.data());
    blake2s_init(*state, HASH_SIZE, nullptr, 0);
}

Blake2sContext::Blake2sContext(std::span<const uint8_t> key) {
    ensure_sodium_initialized();
    if (key.size() > 32) {
        throw std::runtime_error("BLAKE2s key must be at most 32 bytes");
    }
    static_assert(sizeof(Blake2sState) <= sizeof(state_buffer_));
    auto* state = reinterpret_cast<Blake2sState*>(state_buffer_.data());
    blake2s_init(*state, HASH_SIZE, key.data(), key.size());
}

void Blake2sContext::update(std::span<const uint8_t> data) {
    auto* state = reinterpret_cast<Blake2sState*>(state_buffer_.data());
    blake2s_update(*state, data.data(), data.size());
}

void Blake2sContext::update(std::string_view data) {
    update({reinterpret_cast<const uint8_t*>(data.data()), data.size()});
}

Hash Blake2sContext::finalize() {
    Hash result;
    auto* state = reinterpret_cast<Blake2sState*>(state_buffer_.data());
    blake2s_final(*state, result.data(), HASH_SIZE);
    return result;
}

void Blake2sContext::reset() {
    auto* state = reinterpret_cast<Blake2sState*>(state_buffer_.data());
    blake2s_init(*state, HASH_SIZE, nullptr, 0);
}

void Blake2sContext::reset(std::span<const uint8_t> key) {
    if (key.size() > 32) {
        throw std::runtime_error("BLAKE2s key must be at most 32 bytes");
    }
    auto* state = reinterpret_cast<Blake2sState*>(state_buffer_.data());
    blake2s_init(*state, HASH_SIZE, key.data(), key.size());
}

namespace {
std::string hex_string(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
    return oss.str();
}
} // anonymous namespace

Hash construction_hash() {
    auto result = blake2s({reinterpret_cast<const uint8_t*>(NOISE_CONSTRUCTION.data()),
                    NOISE_CONSTRUCTION.size()});
    LOG_DEBUG("construction_hash = {}", hex_string(result.data(), HASH_SIZE));
    return result;
}

Hash identifier_hash() {
    auto ch = construction_hash();
    return mix_hash(ch, {reinterpret_cast<const uint8_t*>(WG_IDENTIFIER.data()),
                        WG_IDENTIFIER.size()});
}

} // namespace vpn::crypto
