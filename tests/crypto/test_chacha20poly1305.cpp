#include <catch2/catch_test_macros.hpp>
#include "vpn/crypto/chacha20poly1305.hpp"
#include <sodium.h>

using namespace vpn::crypto;

TEST_CASE("ChaCha20-Poly1305 basic operations", "[crypto][chacha20poly1305]") {
    // Generate a random key
    SymmetricKey key;
    randombytes_buf(key.data(), KEY_SIZE);

    ChaCha20Poly1305 cipher(key);

    SECTION("Encrypt and decrypt empty message") {
        std::vector<uint8_t> plaintext;
        std::vector<uint8_t> aad;

        auto ciphertext = cipher.encrypt(plaintext, aad, 0);
        REQUIRE(ciphertext.size() == TAG_SIZE);  // Only tag, no data

        auto decrypted = cipher.decrypt(ciphertext, aad, 0);
        REQUIRE(decrypted.has_value());
        REQUIRE(decrypted->empty());
    }

    SECTION("Encrypt and decrypt message") {
        std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
        std::vector<uint8_t> aad = {0xAA, 0xBB};

        auto ciphertext = cipher.encrypt(plaintext, aad, 1);
        REQUIRE(ciphertext.size() == plaintext.size() + TAG_SIZE);

        auto decrypted = cipher.decrypt(ciphertext, aad, 1);
        REQUIRE(decrypted.has_value());
        REQUIRE(*decrypted == plaintext);
    }

    SECTION("Wrong counter fails decryption") {
        std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03};
        std::vector<uint8_t> aad;

        auto ciphertext = cipher.encrypt(plaintext, aad, 0);
        auto decrypted = cipher.decrypt(ciphertext, aad, 1);  // Wrong counter
        REQUIRE_FALSE(decrypted.has_value());
    }

    SECTION("Wrong AAD fails decryption") {
        std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03};
        std::vector<uint8_t> aad1 = {0xAA};
        std::vector<uint8_t> aad2 = {0xBB};

        auto ciphertext = cipher.encrypt(plaintext, aad1, 0);
        auto decrypted = cipher.decrypt(ciphertext, aad2, 0);  // Wrong AAD
        REQUIRE_FALSE(decrypted.has_value());
    }

    SECTION("Tampered ciphertext fails decryption") {
        std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04};
        std::vector<uint8_t> aad;

        auto ciphertext = cipher.encrypt(plaintext, aad, 0);
        ciphertext[0] ^= 0xFF;  // Tamper with first byte

        auto decrypted = cipher.decrypt(ciphertext, aad, 0);
        REQUIRE_FALSE(decrypted.has_value());
    }
}

TEST_CASE("ChaCha20-Poly1305 in-place operations", "[crypto][chacha20poly1305]") {
    SymmetricKey key;
    randombytes_buf(key.data(), KEY_SIZE);

    ChaCha20Poly1305 cipher(key);

    SECTION("In-place encrypt and decrypt") {
        std::vector<uint8_t> original = {0x01, 0x02, 0x03, 0x04, 0x05};
        std::vector<uint8_t> buffer(original.size() + TAG_SIZE);
        std::memcpy(buffer.data(), original.data(), original.size());

        std::vector<uint8_t> aad = {0xAA};

        // Encrypt in place
        size_t ct_len = cipher.encrypt_in_place(buffer, original.size(), aad, 0);
        REQUIRE(ct_len == original.size() + TAG_SIZE);

        // Decrypt in place
        auto pt_len = cipher.decrypt_in_place(buffer, ct_len, aad, 0);
        REQUIRE(pt_len.has_value());
        REQUIRE(*pt_len == original.size());

        // Verify decrypted data
        for (size_t i = 0; i < original.size(); ++i) {
            REQUIRE(buffer[i] == original[i]);
        }
    }
}

TEST_CASE("ChaCha20-Poly1305 nonce format", "[crypto][chacha20poly1305]") {
    // WireGuard uses 4 zero bytes + 8 byte LE counter

    SymmetricKey key;
    randombytes_buf(key.data(), KEY_SIZE);

    ChaCha20Poly1305 cipher(key);

    SECTION("Different counters produce different ciphertexts") {
        std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04};
        std::vector<uint8_t> aad;

        auto ct1 = cipher.encrypt(plaintext, aad, 0);
        auto ct2 = cipher.encrypt(plaintext, aad, 1);

        REQUIRE(ct1 != ct2);
    }

    SECTION("Large counter values work") {
        std::vector<uint8_t> plaintext = {0x01};
        std::vector<uint8_t> aad;

        Counter large_counter = 0xFFFFFFFFFFFFFFFF;
        auto ciphertext = cipher.encrypt(plaintext, aad, large_counter);
        auto decrypted = cipher.decrypt(ciphertext, aad, large_counter);

        REQUIRE(decrypted.has_value());
        REQUIRE(*decrypted == plaintext);
    }
}

TEST_CASE("ChaCha20-Poly1305 RFC 7539 test vector", "[crypto][chacha20poly1305]") {
    // RFC 7539 Section 2.8.2 test vector
    uint8_t key_bytes[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };

    SymmetricKey key;
    std::memcpy(key.data(), key_bytes, 32);

    ChaCha20Poly1305 cipher(key);

    // Note: RFC 7539 uses a different nonce format than WireGuard
    // WireGuard: 4 zero bytes + 8 byte counter
    // RFC 7539: 12 byte nonce

    // We test that our implementation works correctly with the WireGuard format
    std::string plaintext_str = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    std::vector<uint8_t> plaintext(plaintext_str.begin(), plaintext_str.end());

    std::vector<uint8_t> aad = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    };

    // Our format doesn't match RFC 7539 exactly, but we can verify round-trip
    auto ciphertext = cipher.encrypt(plaintext, aad, 0x4746454443424140ULL);
    auto decrypted = cipher.decrypt(ciphertext, aad, 0x4746454443424140ULL);

    REQUIRE(decrypted.has_value());
    REQUIRE(*decrypted == plaintext);
}

TEST_CASE("XChaCha20-Poly1305 basic operations", "[crypto][xchacha20poly1305]") {
    SymmetricKey key;
    randombytes_buf(key.data(), KEY_SIZE);

    XChaCha20Poly1305 cipher(key);

    std::array<uint8_t, 24> nonce;
    randombytes_buf(nonce.data(), 24);

    SECTION("Encrypt and decrypt") {
        std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
        std::vector<uint8_t> aad = {0xAA, 0xBB};

        auto ciphertext = cipher.encrypt(plaintext, aad, nonce);
        REQUIRE(ciphertext.size() == plaintext.size() + TAG_SIZE);

        auto decrypted = cipher.decrypt(ciphertext, aad, nonce);
        REQUIRE(decrypted.has_value());
        REQUIRE(*decrypted == plaintext);
    }

    SECTION("Wrong nonce fails decryption") {
        std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03};
        std::vector<uint8_t> aad;

        auto ciphertext = cipher.encrypt(plaintext, aad, nonce);

        std::array<uint8_t, 24> wrong_nonce;
        randombytes_buf(wrong_nonce.data(), 24);

        auto decrypted = cipher.decrypt(ciphertext, aad, wrong_nonce);
        REQUIRE_FALSE(decrypted.has_value());
    }
}
