#include <catch2/catch_test_macros.hpp>
#include "vpn/crypto/curve25519.hpp"
#include <sodium.h>

using namespace vpn::crypto;

TEST_CASE("Curve25519 key generation", "[crypto][curve25519]") {
    SECTION("Generate random keypair") {
        auto kp = Curve25519KeyPair::generate();

        // Keys should not be all zeros
        bool private_all_zero = true;
        bool public_all_zero = true;
        for (size_t i = 0; i < KEY_SIZE; ++i) {
            if (kp.private_key()[i] != 0) private_all_zero = false;
            if (kp.public_key()[i] != 0) public_all_zero = false;
        }
        REQUIRE_FALSE(private_all_zero);
        REQUIRE_FALSE(public_all_zero);
    }

    SECTION("Multiple keypairs are different") {
        auto kp1 = Curve25519KeyPair::generate();
        auto kp2 = Curve25519KeyPair::generate();

        REQUIRE(kp1.private_key() != kp2.private_key());
        REQUIRE(kp1.public_key() != kp2.public_key());
    }

    SECTION("Derive public key from private key") {
        auto kp1 = Curve25519KeyPair::generate();
        auto kp2 = Curve25519KeyPair::from_private_key(kp1.private_key());

        REQUIRE(kp1.private_key() == kp2.private_key());
        REQUIRE(kp1.public_key() == kp2.public_key());
    }
}

TEST_CASE("Curve25519 base64 encoding", "[crypto][curve25519]") {
    SECTION("Round-trip encoding") {
        auto kp = Curve25519KeyPair::generate();

        auto private_b64 = kp.private_key_base64();
        auto public_b64 = kp.public_key_base64();

        // Base64 encoded 32 bytes = 44 characters (with padding)
        REQUIRE(private_b64.size() == 44);
        REQUIRE(public_b64.size() == 44);

        // Can reconstruct from base64
        auto kp2 = Curve25519KeyPair::from_base64(private_b64);
        REQUIRE(kp2.has_value());
        REQUIRE(kp2->public_key() == kp.public_key());
    }

    SECTION("Invalid base64 returns nullopt") {
        auto result = Curve25519KeyPair::from_base64("not-valid-base64!");
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Wrong length returns nullopt") {
        auto result = Curve25519KeyPair::from_base64("AAAA");  // Too short
        REQUIRE_FALSE(result.has_value());
    }
}

TEST_CASE("X25519 Diffie-Hellman", "[crypto][curve25519]") {
    SECTION("Shared secret computation") {
        auto alice = Curve25519KeyPair::generate();
        auto bob = Curve25519KeyPair::generate();

        // Alice computes shared secret
        auto shared_alice = x25519(alice.private_key(), bob.public_key());

        // Bob computes shared secret
        auto shared_bob = x25519(bob.private_key(), alice.public_key());

        // Both should arrive at the same shared secret
        REQUIRE(shared_alice == shared_bob);
    }

    SECTION("Different key pairs yield different shared secrets") {
        auto alice = Curve25519KeyPair::generate();
        auto bob1 = Curve25519KeyPair::generate();
        auto bob2 = Curve25519KeyPair::generate();

        auto shared1 = x25519(alice.private_key(), bob1.public_key());
        auto shared2 = x25519(alice.private_key(), bob2.public_key());

        REQUIRE(shared1 != shared2);
    }

    SECTION("Known test vector") {
        // RFC 7748 test vector
        uint8_t scalar[32] = {
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d,
            0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
            0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18,
            0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4
        };
        uint8_t point[32] = {
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb,
            0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
            0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
            0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c
        };
        uint8_t expected[32] = {
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90,
            0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
            0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7,
            0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52
        };

        PrivateKey sk;
        PublicKey pk;
        std::memcpy(sk.data(), scalar, 32);
        std::memcpy(pk.data(), point, 32);

        auto result = x25519(sk, pk);

        for (size_t i = 0; i < 32; ++i) {
            REQUIRE(result[i] == expected[i]);
        }
    }
}

TEST_CASE("Private key clamping", "[crypto][curve25519]") {
    SECTION("Clamping sets correct bits") {
        PrivateKey key;
        // Fill with all 0xFF
        std::memset(key.data(), 0xFF, KEY_SIZE);

        clamp_private_key(key);

        // Check clamping: key[0] &= 248, key[31] &= 127, key[31] |= 64
        REQUIRE((key[0] & 0x07) == 0);   // Bottom 3 bits clear
        REQUIRE((key[31] & 0x80) == 0);  // Top bit clear
        REQUIRE((key[31] & 0x40) != 0);  // Second-to-top bit set
    }
}
