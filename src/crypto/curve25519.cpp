#include "vpn/crypto/curve25519.hpp"
#include "vpn/util/base64.hpp"
#include <sodium.h>
#include <stdexcept>

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

Curve25519KeyPair Curve25519KeyPair::generate() {
    ensure_sodium_initialized();

    Curve25519KeyPair kp;
    crypto_box_keypair(kp.public_key_.data(), kp.private_key_.data());
    return kp;
}

Curve25519KeyPair Curve25519KeyPair::from_private_key(const PrivateKey& private_key) {
    ensure_sodium_initialized();

    Curve25519KeyPair kp;
    std::memcpy(kp.private_key_.data(), private_key.data(), KEY_SIZE);

    // Derive public key from private key
    crypto_scalarmult_base(kp.public_key_.data(), kp.private_key_.data());
    return kp;
}

std::optional<Curve25519KeyPair> Curve25519KeyPair::from_base64(std::string_view base64_private) {
    auto decoded = util::base64_decode(base64_private);
    if (!decoded || decoded->size() != KEY_SIZE) {
        return std::nullopt;
    }

    PrivateKey pk;
    std::memcpy(pk.data(), decoded->data(), KEY_SIZE);
    return from_private_key(pk);
}

std::string Curve25519KeyPair::private_key_base64() const {
    return util::base64_encode({private_key_.data(), KEY_SIZE});
}

std::string Curve25519KeyPair::public_key_base64() const {
    return util::base64_encode({public_key_.data(), KEY_SIZE});
}

SharedSecret x25519(const PrivateKey& private_key, const PublicKey& public_key) {
    ensure_sodium_initialized();

    SharedSecret secret;
    if (crypto_scalarmult(secret.data(), private_key.data(), public_key.data()) != 0) {
        // This can happen if the public key is a low-order point
        // Return all zeros (will fail subsequent checks)
        secret.clear();
    }
    return secret;
}

void clamp_private_key(PrivateKey& key) {
    // Curve25519 clamping
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
}

} // namespace vpn::crypto
