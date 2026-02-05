#include <catch2/catch_test_macros.hpp>
#include "vpn/crypto/noise.hpp"
#include <sodium.h>

using namespace vpn::crypto;

TEST_CASE("TAI64N timestamp", "[crypto][noise]") {
    SECTION("Now produces valid timestamp") {
        auto ts = Tai64nTimestamp::now();

        // First byte should be 0x40 (indicates positive time after epoch)
        REQUIRE(ts.bytes[0] == 0x40);
    }

    SECTION("Sequential timestamps are ordered") {
        auto ts1 = Tai64nTimestamp::now();
        // Small delay
        for (volatile int i = 0; i < 10000; ++i) {}
        auto ts2 = Tai64nTimestamp::now();

        REQUIRE(ts2 > ts1);
    }

    SECTION("Timestamp comparison") {
        Tai64nTimestamp ts1{}, ts2{};
        ts1.bytes[0] = 0x40;
        ts2.bytes[0] = 0x40;
        ts1.bytes[7] = 0x01;
        ts2.bytes[7] = 0x02;

        REQUIRE(ts2 > ts1);
        REQUIRE_FALSE(ts1 > ts2);
    }
}

TEST_CASE("Noise handshake - basic flow", "[crypto][noise]") {
    // Generate key pairs for initiator and responder
    auto initiator_static = Curve25519KeyPair::generate();
    auto responder_static = Curve25519KeyPair::generate();

    // Create handshakes
    auto initiator = NoiseHandshake::create_initiator(
        initiator_static,
        responder_static.public_key()
    );
    auto responder = NoiseHandshake::create_responder(responder_static);

    SECTION("Initial states are correct") {
        REQUIRE(initiator.state() == NoiseHandshake::State::Initial);
        REQUIRE(responder.state() == NoiseHandshake::State::WaitingForInitiation);
    }

    SECTION("Complete handshake") {
        // Initiator creates initiation message
        auto initiation = initiator.create_initiation();
        REQUIRE(initiation.has_value());
        REQUIRE(initiation->message.size() == 148);
        REQUIRE(initiator.state() == NoiseHandshake::State::WaitingForResponse);

        // Responder processes initiation and creates response
        auto response_result = responder.process_initiation(initiation->message);
        REQUIRE(response_result.has_value());
        REQUIRE(response_result->message.size() == 92);
        REQUIRE(responder.state() == NoiseHandshake::State::Established);

        // Verify responder learned initiator's public key
        REQUIRE(response_result->initiator_public_key == initiator_static.public_key());

        // Initiator processes response
        auto initiator_keys = initiator.process_response(response_result->message);
        REQUIRE(initiator_keys.has_value());
        REQUIRE(initiator.state() == NoiseHandshake::State::Established);

        // Get responder's keys
        auto responder_keys = responder.finalize();
        REQUIRE(responder_keys.has_value());

        // Verify session keys match (send/receive are swapped)
        REQUIRE(initiator_keys->send_key == responder_keys->receive_key);
        REQUIRE(initiator_keys->receive_key == responder_keys->send_key);

        // Verify indices
        REQUIRE(initiator_keys->sender_index == initiation->sender_index);
        REQUIRE(initiator_keys->receiver_index == response_result->sender_index);
        REQUIRE(responder_keys->sender_index == response_result->sender_index);
        REQUIRE(responder_keys->receiver_index == initiation->sender_index);
    }
}

TEST_CASE("Noise handshake - with pre-shared key", "[crypto][noise]") {
    auto initiator_static = Curve25519KeyPair::generate();
    auto responder_static = Curve25519KeyPair::generate();

    PresharedKey psk;
    randombytes_buf(psk.data(), KEY_SIZE);

    auto initiator = NoiseHandshake::create_initiator(
        initiator_static,
        responder_static.public_key(),
        psk
    );
    auto responder = NoiseHandshake::create_responder(responder_static, psk);

    SECTION("Handshake succeeds with matching PSK") {
        auto initiation = initiator.create_initiation();
        REQUIRE(initiation.has_value());

        auto response = responder.process_initiation(initiation->message);
        REQUIRE(response.has_value());

        auto keys = initiator.process_response(response->message);
        REQUIRE(keys.has_value());
    }

    SECTION("Handshake fails with mismatched PSK") {
        PresharedKey wrong_psk;
        randombytes_buf(wrong_psk.data(), KEY_SIZE);

        auto wrong_responder = NoiseHandshake::create_responder(responder_static, wrong_psk);

        auto initiation = initiator.create_initiation();
        REQUIRE(initiation.has_value());

        // This should fail because PSK doesn't match
        auto response = wrong_responder.process_initiation(initiation->message);
        // The failure might happen at different points depending on implementation
        // Either process_initiation fails or process_response fails
        if (response.has_value()) {
            auto keys = initiator.process_response(response->message);
            REQUIRE_FALSE(keys.has_value());
        }
    }
}

TEST_CASE("Noise handshake - invalid messages", "[crypto][noise]") {
    auto initiator_static = Curve25519KeyPair::generate();
    auto responder_static = Curve25519KeyPair::generate();

    SECTION("Wrong message type rejected") {
        auto responder = NoiseHandshake::create_responder(responder_static);

        std::vector<uint8_t> fake_initiation(148, 0);
        fake_initiation[0] = 0x02;  // Response type instead of initiation

        auto result = responder.process_initiation(fake_initiation);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Truncated initiation rejected") {
        auto responder = NoiseHandshake::create_responder(responder_static);

        std::vector<uint8_t> truncated(100, 0);  // Too short
        truncated[0] = 0x01;

        auto result = responder.process_initiation(truncated);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Truncated response rejected") {
        auto initiator = NoiseHandshake::create_initiator(
            initiator_static,
            responder_static.public_key()
        );

        auto initiation = initiator.create_initiation();
        REQUIRE(initiation.has_value());

        std::vector<uint8_t> truncated(50, 0);  // Too short
        truncated[0] = 0x02;

        auto result = initiator.process_response(truncated);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Wrong receiver index rejected") {
        auto initiator = NoiseHandshake::create_initiator(
            initiator_static,
            responder_static.public_key()
        );
        auto responder = NoiseHandshake::create_responder(responder_static);

        auto initiation = initiator.create_initiation();
        REQUIRE(initiation.has_value());

        auto response = responder.process_initiation(initiation->message);
        REQUIRE(response.has_value());

        // Corrupt the receiver index
        response->message[8] ^= 0xFF;
        response->message[9] ^= 0xFF;
        response->message[10] ^= 0xFF;
        response->message[11] ^= 0xFF;

        auto keys = initiator.process_response(response->message);
        REQUIRE_FALSE(keys.has_value());
    }
}

TEST_CASE("Noise handshake - state machine", "[crypto][noise]") {
    auto initiator_static = Curve25519KeyPair::generate();
    auto responder_static = Curve25519KeyPair::generate();

    SECTION("Cannot create initiation twice") {
        auto initiator = NoiseHandshake::create_initiator(
            initiator_static,
            responder_static.public_key()
        );

        auto init1 = initiator.create_initiation();
        REQUIRE(init1.has_value());

        auto init2 = initiator.create_initiation();
        REQUIRE_FALSE(init2.has_value());
    }

    SECTION("Cannot process response without initiation") {
        auto initiator = NoiseHandshake::create_initiator(
            initiator_static,
            responder_static.public_key()
        );

        std::vector<uint8_t> fake_response(92, 0);
        fake_response[0] = 0x02;

        auto result = initiator.process_response(fake_response);
        REQUIRE_FALSE(result.has_value());
    }

    SECTION("Responder cannot process initiation twice") {
        auto initiator1 = NoiseHandshake::create_initiator(
            initiator_static,
            responder_static.public_key()
        );
        auto initiator2 = NoiseHandshake::create_initiator(
            Curve25519KeyPair::generate(),
            responder_static.public_key()
        );
        auto responder = NoiseHandshake::create_responder(responder_static);

        auto init1 = initiator1.create_initiation();
        auto init2 = initiator2.create_initiation();

        auto result1 = responder.process_initiation(init1->message);
        REQUIRE(result1.has_value());

        auto result2 = responder.process_initiation(init2->message);
        REQUIRE_FALSE(result2.has_value());
    }
}

TEST_CASE("MAC computation", "[crypto][noise]") {
    auto keypair = Curve25519KeyPair::generate();

    SECTION("MAC1 is deterministic") {
        std::vector<uint8_t> message = {0x01, 0x02, 0x03, 0x04, 0x05};

        auto mac1 = compute_mac1(keypair.public_key(), message);
        auto mac2 = compute_mac1(keypair.public_key(), message);

        REQUIRE(std::memcmp(mac1.data(), mac2.data(), 16) == 0);
    }

    SECTION("Different messages have different MACs") {
        std::vector<uint8_t> message1 = {0x01, 0x02, 0x03};
        std::vector<uint8_t> message2 = {0x01, 0x02, 0x04};

        auto mac1 = compute_mac1(keypair.public_key(), message1);
        auto mac2 = compute_mac1(keypair.public_key(), message2);

        REQUIRE(std::memcmp(mac1.data(), mac2.data(), 16) != 0);
    }

    SECTION("MAC2 with cookie") {
        std::array<uint8_t, 16> cookie;
        randombytes_buf(cookie.data(), 16);

        std::vector<uint8_t> message = {0x01, 0x02, 0x03, 0x04, 0x05};

        auto mac2 = compute_mac2(cookie, message);

        // Should not be all zeros
        bool all_zero = true;
        for (size_t i = 0; i < 16; ++i) {
            if (mac2[i] != 0) all_zero = false;
        }
        REQUIRE_FALSE(all_zero);
    }
}

TEST_CASE("Cookie generator", "[crypto][noise]") {
    auto server_keypair = Curve25519KeyPair::generate();
    CookieGenerator generator(server_keypair.public_key());

    auto peer_keypair = Curve25519KeyPair::generate();
    std::vector<uint8_t> source_addr = {192, 168, 1, 100, 0x1F, 0x90};  // IP:port

    SECTION("Generated cookie is valid") {
        auto cookie = generator.generate_cookie(source_addr, peer_keypair.public_key());

        bool valid = generator.validate_cookie(
            cookie,
            source_addr,
            peer_keypair.public_key()
        );
        REQUIRE(valid);
    }

    SECTION("Different source addresses get different cookies") {
        std::vector<uint8_t> addr1 = {192, 168, 1, 100, 0x1F, 0x90};
        std::vector<uint8_t> addr2 = {192, 168, 1, 101, 0x1F, 0x90};

        auto cookie1 = generator.generate_cookie(addr1, peer_keypair.public_key());
        auto cookie2 = generator.generate_cookie(addr2, peer_keypair.public_key());

        REQUIRE(std::memcmp(cookie1.data(), cookie2.data(), 16) != 0);
    }

    SECTION("Cookie invalid for different source") {
        auto cookie = generator.generate_cookie(source_addr, peer_keypair.public_key());

        std::vector<uint8_t> different_addr = {192, 168, 1, 200, 0x1F, 0x90};

        bool valid = generator.validate_cookie(
            cookie,
            different_addr,
            peer_keypair.public_key()
        );
        REQUIRE_FALSE(valid);
    }

    SECTION("Cookie valid after secret rotation") {
        auto cookie = generator.generate_cookie(source_addr, peer_keypair.public_key());

        generator.rotate_secret();

        // Should still be valid (using prev_secret)
        bool valid = generator.validate_cookie(
            cookie,
            source_addr,
            peer_keypair.public_key()
        );
        REQUIRE(valid);

        // After second rotation, original cookie should be invalid
        generator.rotate_secret();
        valid = generator.validate_cookie(
            cookie,
            source_addr,
            peer_keypair.public_key()
        );
        REQUIRE_FALSE(valid);
    }
}
