#include "vpn/crypto/chacha20poly1305.hpp"
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

} // anonymous namespace

ChaCha20Poly1305::ChaCha20Poly1305(const SymmetricKey& key) {
    ensure_sodium_initialized();
    std::memcpy(key_.data(), key.data(), KEY_SIZE);
}

Nonce ChaCha20Poly1305::make_nonce(Counter counter) {
    // WireGuard nonce format: 4 zero bytes followed by 8-byte little-endian counter
    Nonce nonce{};
    // First 4 bytes are zero (already initialized)
    // Next 8 bytes are the little-endian counter
    for (int i = 0; i < 8; ++i) {
        nonce[4 + i] = static_cast<uint8_t>((counter >> (8 * i)) & 0xFF);
    }
    return nonce;
}

std::vector<uint8_t> ChaCha20Poly1305::encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> additional_data,
    Counter counter
) const {
    std::vector<uint8_t> ciphertext(plaintext.size() + TAG_SIZE);
    unsigned long long ciphertext_len = 0;

    Nonce nonce = make_nonce(counter);

    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_len,
        plaintext.data(), plaintext.size(),
        additional_data.data(), additional_data.size(),
        nullptr,  // nsec (not used)
        nonce.data(),
        key_.data()
    );

    ciphertext.resize(static_cast<size_t>(ciphertext_len));
    return ciphertext;
}

size_t ChaCha20Poly1305::encrypt_in_place(
    std::span<uint8_t> buffer,
    size_t plaintext_len,
    std::span<const uint8_t> additional_data,
    Counter counter
) const {
    if (buffer.size() < plaintext_len + TAG_SIZE) {
        throw std::runtime_error("Buffer too small for encryption");
    }

    unsigned long long ciphertext_len = 0;
    Nonce nonce = make_nonce(counter);

    crypto_aead_chacha20poly1305_ietf_encrypt(
        buffer.data(), &ciphertext_len,
        buffer.data(), plaintext_len,
        additional_data.data(), additional_data.size(),
        nullptr,
        nonce.data(),
        key_.data()
    );

    return static_cast<size_t>(ciphertext_len);
}

std::optional<std::vector<uint8_t>> ChaCha20Poly1305::decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> additional_data,
    Counter counter
) const {
    if (ciphertext.size() < TAG_SIZE) {
        return std::nullopt;
    }

    std::vector<uint8_t> plaintext(ciphertext.size() - TAG_SIZE);
    unsigned long long plaintext_len = 0;

    Nonce nonce = make_nonce(counter);

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,  // nsec (not used)
            ciphertext.data(), ciphertext.size(),
            additional_data.data(), additional_data.size(),
            nonce.data(),
            key_.data()
        ) != 0) {
        return std::nullopt;
    }

    plaintext.resize(static_cast<size_t>(plaintext_len));
    return plaintext;
}

std::optional<size_t> ChaCha20Poly1305::decrypt_in_place(
    std::span<uint8_t> buffer,
    size_t ciphertext_len,
    std::span<const uint8_t> additional_data,
    Counter counter
) const {
    if (ciphertext_len < TAG_SIZE) {
        return std::nullopt;
    }

    unsigned long long plaintext_len = 0;
    Nonce nonce = make_nonce(counter);

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            buffer.data(), &plaintext_len,
            nullptr,
            buffer.data(), ciphertext_len,
            additional_data.data(), additional_data.size(),
            nonce.data(),
            key_.data()
        ) != 0) {
        return std::nullopt;
    }

    return static_cast<size_t>(plaintext_len);
}

// XChaCha20-Poly1305 implementation

XChaCha20Poly1305::XChaCha20Poly1305(const SymmetricKey& key) {
    ensure_sodium_initialized();
    std::memcpy(key_.data(), key.data(), KEY_SIZE);
}

std::vector<uint8_t> XChaCha20Poly1305::encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> additional_data,
    std::span<const uint8_t, NONCE_SIZE> nonce
) const {
    std::vector<uint8_t> ciphertext(plaintext.size() + TAG_SIZE);
    unsigned long long ciphertext_len = 0;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_len,
        plaintext.data(), plaintext.size(),
        additional_data.data(), additional_data.size(),
        nullptr,
        nonce.data(),
        key_.data()
    );

    ciphertext.resize(static_cast<size_t>(ciphertext_len));
    return ciphertext;
}

std::optional<std::vector<uint8_t>> XChaCha20Poly1305::decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> additional_data,
    std::span<const uint8_t, NONCE_SIZE> nonce
) const {
    if (ciphertext.size() < TAG_SIZE) {
        return std::nullopt;
    }

    std::vector<uint8_t> plaintext(ciphertext.size() - TAG_SIZE);
    unsigned long long plaintext_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            ciphertext.data(), ciphertext.size(),
            additional_data.data(), additional_data.size(),
            nonce.data(),
            key_.data()
        ) != 0) {
        return std::nullopt;
    }

    plaintext.resize(static_cast<size_t>(plaintext_len));
    return plaintext;
}

} // namespace vpn::crypto
