#pragma once

#include "types.hpp"
#include <optional>
#include <string>
#include <string_view>

namespace vpn::crypto {

// Curve25519 key pair for Diffie-Hellman key exchange
class Curve25519KeyPair {
public:
    // Generate a new random key pair
    static Curve25519KeyPair generate();

    // Create from existing private key (derives public key)
    static Curve25519KeyPair from_private_key(const PrivateKey& private_key);

    // Load from base64-encoded private key
    static std::optional<Curve25519KeyPair> from_base64(std::string_view base64_private);

    // Get the private key
    const PrivateKey& private_key() const { return private_key_; }

    // Get the public key
    const PublicKey& public_key() const { return public_key_; }

    // Export private key as base64
    std::string private_key_base64() const;

    // Export public key as base64
    std::string public_key_base64() const;

    // Default constructor (creates empty keys)
    Curve25519KeyPair() = default;

private:
    PrivateKey private_key_;
    PublicKey public_key_;
};

// Perform X25519 Diffie-Hellman key exchange
// Returns shared secret from our private key and their public key
SharedSecret x25519(const PrivateKey& private_key, const PublicKey& public_key);

// Clamp a private key according to Curve25519 spec
void clamp_private_key(PrivateKey& key);

} // namespace vpn::crypto
