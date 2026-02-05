#include <catch2/catch_test_macros.hpp>
#include "vpn/crypto/blake2s.hpp"
#include <sodium.h>

using namespace vpn::crypto;

TEST_CASE("BLAKE2s basic hashing", "[crypto][blake2s]") {
    SECTION("Empty input") {
        std::vector<uint8_t> empty;
        auto hash = blake2s(empty);

        // Hash should not be all zeros
        bool all_zero = true;
        for (size_t i = 0; i < HASH_SIZE; ++i) {
            if (hash[i] != 0) all_zero = false;
        }
        REQUIRE_FALSE(all_zero);
    }

    SECTION("Same input gives same hash") {
        std::vector<uint8_t> data = {0x01, 0x02, 0x03};
        auto hash1 = blake2s(data);
        auto hash2 = blake2s(data);

        REQUIRE(hash1 == hash2);
    }

    SECTION("Different inputs give different hashes") {
        std::vector<uint8_t> data1 = {0x01, 0x02, 0x03};
        std::vector<uint8_t> data2 = {0x01, 0x02, 0x04};

        auto hash1 = blake2s(data1);
        auto hash2 = blake2s(data2);

        REQUIRE(hash1 != hash2);
    }
}

TEST_CASE("BLAKE2s keyed hashing", "[crypto][blake2s]") {
    SECTION("Keyed hash differs from unkeyed") {
        std::vector<uint8_t> data = {0x01, 0x02, 0x03};
        std::vector<uint8_t> key = {0xAA, 0xBB, 0xCC, 0xDD};

        auto unkeyed = blake2s(data);
        auto keyed = blake2s_keyed(key, data);

        REQUIRE(unkeyed != keyed);
    }

    SECTION("Different keys give different hashes") {
        std::vector<uint8_t> data = {0x01, 0x02, 0x03};
        std::vector<uint8_t> key1 = {0xAA, 0xBB, 0xCC, 0xDD};
        std::vector<uint8_t> key2 = {0xAA, 0xBB, 0xCC, 0xDE};

        auto hash1 = blake2s_keyed(key1, data);
        auto hash2 = blake2s_keyed(key2, data);

        REQUIRE(hash1 != hash2);
    }
}

TEST_CASE("BLAKE2s HMAC", "[crypto][blake2s]") {
    SECTION("HMAC produces consistent results") {
        std::vector<uint8_t> key = {0x01, 0x02, 0x03, 0x04};
        std::vector<uint8_t> data = {0x0A, 0x0B, 0x0C};

        auto hmac1 = hmac_blake2s(key, data);
        auto hmac2 = hmac_blake2s(key, data);

        REQUIRE(hmac1 == hmac2);
    }

    SECTION("Different keys produce different HMACs") {
        std::vector<uint8_t> key1 = {0x01, 0x02, 0x03, 0x04};
        std::vector<uint8_t> key2 = {0x01, 0x02, 0x03, 0x05};
        std::vector<uint8_t> data = {0x0A, 0x0B, 0x0C};

        auto hmac1 = hmac_blake2s(key1, data);
        auto hmac2 = hmac_blake2s(key2, data);

        REQUIRE(hmac1 != hmac2);
    }
}

TEST_CASE("HKDF operations", "[crypto][blake2s]") {
    SECTION("HKDF extract produces non-zero output") {
        std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04};
        std::vector<uint8_t> ikm = {0x0A, 0x0B, 0x0C, 0x0D};

        auto prk = hkdf_extract(salt, ikm);

        bool all_zero = true;
        for (size_t i = 0; i < HASH_SIZE; ++i) {
            if (prk[i] != 0) all_zero = false;
        }
        REQUIRE_FALSE(all_zero);
    }

    SECTION("HKDF expand produces correct number of keys") {
        Hash prk;
        randombytes_buf(prk.data(), HASH_SIZE);

        auto keys1 = hkdf_expand<1>(prk);
        REQUIRE(keys1.size() == 1);

        auto keys2 = hkdf_expand<2>(prk);
        REQUIRE(keys2.size() == 2);

        auto keys3 = hkdf_expand<3>(prk);
        REQUIRE(keys3.size() == 3);
    }

    SECTION("HKDF produces different keys") {
        Hash prk;
        randombytes_buf(prk.data(), HASH_SIZE);

        auto keys = hkdf_expand<3>(prk);

        REQUIRE(keys[0] != keys[1]);
        REQUIRE(keys[1] != keys[2]);
        REQUIRE(keys[0] != keys[2]);
    }

    SECTION("Full HKDF round trip") {
        std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04};
        std::vector<uint8_t> ikm = {0x0A, 0x0B, 0x0C, 0x0D};
        std::vector<uint8_t> info = {0xF0, 0xF1, 0xF2};

        auto keys = hkdf<2>(salt, ikm, info);

        // Keys should be different and non-zero
        REQUIRE(keys[0] != keys[1]);

        bool all_zero = true;
        for (size_t i = 0; i < KEY_SIZE; ++i) {
            if (keys[0][i] != 0 || keys[1][i] != 0) all_zero = false;
        }
        REQUIRE_FALSE(all_zero);
    }
}

TEST_CASE("WireGuard KDF operations", "[crypto][blake2s]") {
    SECTION("mix_key produces new keys") {
        SymmetricKey ck;
        randombytes_buf(ck.data(), KEY_SIZE);

        std::vector<uint8_t> ikm = {0x01, 0x02, 0x03, 0x04};

        auto result = mix_key(ck, ikm);

        // New chaining key should differ from old
        REQUIRE(result.chaining_key != ck);
        // Output key should differ from chaining key
        REQUIRE(result.output_key != result.chaining_key);
    }

    SECTION("mix_hash produces new hash") {
        Hash hash;
        randombytes_buf(hash.data(), HASH_SIZE);

        std::vector<uint8_t> data = {0x01, 0x02, 0x03};

        auto new_hash = mix_hash(hash, data);

        REQUIRE(new_hash != hash);
    }
}

TEST_CASE("Blake2sContext incremental hashing", "[crypto][blake2s]") {
    SECTION("Context produces non-zero output") {
        std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        Blake2sContext ctx;
        ctx.update(data);
        auto hash = ctx.finalize();

        // Should not be all zeros
        bool all_zero = true;
        for (size_t i = 0; i < HASH_SIZE; ++i) {
            if (hash[i] != 0) all_zero = false;
        }
        REQUIRE_FALSE(all_zero);
    }

    SECTION("Different inputs give different hashes") {
        std::vector<uint8_t> data1 = {0x01, 0x02, 0x03};
        std::vector<uint8_t> data2 = {0x01, 0x02, 0x04};

        Blake2sContext ctx1;
        ctx1.update(data1);
        auto hash1 = ctx1.finalize();

        Blake2sContext ctx2;
        ctx2.update(data2);
        auto hash2 = ctx2.finalize();

        REQUIRE(hash1 != hash2);
    }
}

TEST_CASE("WireGuard protocol hashes", "[crypto][blake2s]") {
    SECTION("Construction hash is deterministic") {
        auto hash1 = construction_hash();
        auto hash2 = construction_hash();

        REQUIRE(hash1 == hash2);
    }

    SECTION("Identifier hash is deterministic") {
        auto hash1 = identifier_hash();
        auto hash2 = identifier_hash();

        REQUIRE(hash1 == hash2);
    }

    SECTION("Construction and identifier hashes differ") {
        auto ch = construction_hash();
        auto ih = identifier_hash();

        REQUIRE(ch != ih);
    }
}
