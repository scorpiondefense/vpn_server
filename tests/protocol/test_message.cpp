#include <catch2/catch_test_macros.hpp>
#include "vpn/protocol/message.hpp"
#include <sodium.h>

using namespace vpn::protocol;

TEST_CASE("Message type detection", "[protocol][message]") {
    SECTION("Handshake initiation") {
        std::vector<uint8_t> data(148, 0);
        data[0] = 1;
        auto type = get_message_type(data);
        REQUIRE(type.has_value());
        REQUIRE(*type == MessageType::HandshakeInitiation);
    }

    SECTION("Handshake response") {
        std::vector<uint8_t> data(92, 0);
        data[0] = 2;
        auto type = get_message_type(data);
        REQUIRE(type.has_value());
        REQUIRE(*type == MessageType::HandshakeResponse);
    }

    SECTION("Cookie reply") {
        std::vector<uint8_t> data(64, 0);
        data[0] = 3;
        auto type = get_message_type(data);
        REQUIRE(type.has_value());
        REQUIRE(*type == MessageType::CookieReply);
    }

    SECTION("Transport data") {
        std::vector<uint8_t> data(32, 0);
        data[0] = 4;
        auto type = get_message_type(data);
        REQUIRE(type.has_value());
        REQUIRE(*type == MessageType::TransportData);
    }

    SECTION("Invalid type") {
        std::vector<uint8_t> data(32, 0);
        data[0] = 5;  // Invalid
        auto type = get_message_type(data);
        REQUIRE_FALSE(type.has_value());
    }

    SECTION("Too short") {
        std::vector<uint8_t> data(3, 0);
        auto type = get_message_type(data);
        REQUIRE_FALSE(type.has_value());
    }
}

TEST_CASE("HandshakeInitiation parsing and serialization", "[protocol][message]") {
    SECTION("Round trip") {
        HandshakeInitiation orig;
        orig.sender_index = 0x12345678;
        randombytes_buf(orig.ephemeral.data(), orig.ephemeral.size());
        randombytes_buf(orig.encrypted_static.data(), orig.encrypted_static.size());
        randombytes_buf(orig.encrypted_timestamp.data(), orig.encrypted_timestamp.size());
        randombytes_buf(orig.mac1.data(), orig.mac1.size());
        randombytes_buf(orig.mac2.data(), orig.mac2.size());

        auto serialized = orig.serialize();
        REQUIRE(serialized.size() == HANDSHAKE_INITIATION_SIZE);
        REQUIRE(serialized[0] == 1);

        auto parsed = HandshakeInitiation::parse(serialized);
        REQUIRE(parsed.has_value());
        REQUIRE(parsed->sender_index == orig.sender_index);
        REQUIRE(parsed->ephemeral == orig.ephemeral);
        REQUIRE(parsed->encrypted_static == orig.encrypted_static);
        REQUIRE(parsed->encrypted_timestamp == orig.encrypted_timestamp);
        REQUIRE(parsed->mac1 == orig.mac1);
        REQUIRE(parsed->mac2 == orig.mac2);
    }

    SECTION("Wrong size") {
        std::vector<uint8_t> data(100, 0);
        data[0] = 1;
        auto parsed = HandshakeInitiation::parse(data);
        REQUIRE_FALSE(parsed.has_value());
    }

    SECTION("Wrong type") {
        std::vector<uint8_t> data(148, 0);
        data[0] = 2;  // Response type
        auto parsed = HandshakeInitiation::parse(data);
        REQUIRE_FALSE(parsed.has_value());
    }
}

TEST_CASE("HandshakeResponse parsing and serialization", "[protocol][message]") {
    SECTION("Round trip") {
        HandshakeResponse orig;
        orig.sender_index = 0xAABBCCDD;
        orig.receiver_index = 0x11223344;
        randombytes_buf(orig.ephemeral.data(), orig.ephemeral.size());
        randombytes_buf(orig.encrypted_nothing.data(), orig.encrypted_nothing.size());
        randombytes_buf(orig.mac1.data(), orig.mac1.size());
        randombytes_buf(orig.mac2.data(), orig.mac2.size());

        auto serialized = orig.serialize();
        REQUIRE(serialized.size() == HANDSHAKE_RESPONSE_SIZE);
        REQUIRE(serialized[0] == 2);

        auto parsed = HandshakeResponse::parse(serialized);
        REQUIRE(parsed.has_value());
        REQUIRE(parsed->sender_index == orig.sender_index);
        REQUIRE(parsed->receiver_index == orig.receiver_index);
        REQUIRE(parsed->ephemeral == orig.ephemeral);
        REQUIRE(parsed->encrypted_nothing == orig.encrypted_nothing);
        REQUIRE(parsed->mac1 == orig.mac1);
        REQUIRE(parsed->mac2 == orig.mac2);
    }
}

TEST_CASE("CookieReply parsing and serialization", "[protocol][message]") {
    SECTION("Round trip") {
        CookieReply orig;
        orig.receiver_index = 0x55667788;
        randombytes_buf(orig.nonce.data(), orig.nonce.size());
        randombytes_buf(orig.encrypted_cookie.data(), orig.encrypted_cookie.size());

        auto serialized = orig.serialize();
        REQUIRE(serialized.size() == COOKIE_REPLY_SIZE);
        REQUIRE(serialized[0] == 3);

        auto parsed = CookieReply::parse(serialized);
        REQUIRE(parsed.has_value());
        REQUIRE(parsed->receiver_index == orig.receiver_index);
        REQUIRE(parsed->nonce == orig.nonce);
        REQUIRE(parsed->encrypted_cookie == orig.encrypted_cookie);
    }
}

TEST_CASE("TransportData parsing and serialization", "[protocol][message]") {
    SECTION("Round trip") {
        TransportData orig;
        orig.receiver_index = 0xDEADBEEF;
        orig.counter = 0x123456789ABCDEF0ULL;
        orig.encrypted_packet.resize(100);
        randombytes_buf(orig.encrypted_packet.data(), orig.encrypted_packet.size());

        auto serialized = orig.serialize();
        REQUIRE(serialized.size() == TRANSPORT_HEADER_SIZE + orig.encrypted_packet.size());
        REQUIRE(serialized[0] == 4);

        auto parsed = TransportData::parse(serialized);
        REQUIRE(parsed.has_value());
        REQUIRE(parsed->receiver_index == orig.receiver_index);
        REQUIRE(parsed->counter == orig.counter);
        REQUIRE(parsed->encrypted_packet == orig.encrypted_packet);
    }

    SECTION("Variable length payload") {
        TransportData msg;
        msg.receiver_index = 1;
        msg.counter = 0;
        msg.encrypted_packet.resize(1500);
        randombytes_buf(msg.encrypted_packet.data(), msg.encrypted_packet.size());

        auto serialized = msg.serialize();
        auto parsed = TransportData::parse(serialized);

        REQUIRE(parsed.has_value());
        REQUIRE(parsed->encrypted_packet.size() == 1500);
    }

    SECTION("Header writing") {
        std::vector<uint8_t> buffer(32, 0xFF);
        TransportData::write_header(buffer, 0x12345678, 0xFEDCBA9876543210ULL);

        REQUIRE(buffer[0] == 4);  // Type
        REQUIRE(buffer[1] == 0);  // Reserved
        REQUIRE(buffer[2] == 0);
        REQUIRE(buffer[3] == 0);

        // Verify little-endian receiver index
        REQUIRE(buffer[4] == 0x78);
        REQUIRE(buffer[5] == 0x56);
        REQUIRE(buffer[6] == 0x34);
        REQUIRE(buffer[7] == 0x12);

        // Verify little-endian counter
        REQUIRE(buffer[8] == 0x10);
        REQUIRE(buffer[9] == 0x32);
        REQUIRE(buffer[10] == 0x54);
        REQUIRE(buffer[11] == 0x76);
        REQUIRE(buffer[12] == 0x98);
        REQUIRE(buffer[13] == 0xBA);
        REQUIRE(buffer[14] == 0xDC);
        REQUIRE(buffer[15] == 0xFE);
    }
}

TEST_CASE("Generic message parsing", "[protocol][message]") {
    SECTION("Parse handshake initiation") {
        std::vector<uint8_t> data(148, 0);
        data[0] = 1;

        auto msg = parse_message(data);
        REQUIRE(msg.has_value());
        REQUIRE(std::holds_alternative<HandshakeInitiation>(*msg));
    }

    SECTION("Parse handshake response") {
        std::vector<uint8_t> data(92, 0);
        data[0] = 2;

        auto msg = parse_message(data);
        REQUIRE(msg.has_value());
        REQUIRE(std::holds_alternative<HandshakeResponse>(*msg));
    }

    SECTION("Parse cookie reply") {
        std::vector<uint8_t> data(64, 0);
        data[0] = 3;

        auto msg = parse_message(data);
        REQUIRE(msg.has_value());
        REQUIRE(std::holds_alternative<CookieReply>(*msg));
    }

    SECTION("Parse transport data") {
        std::vector<uint8_t> data(32, 0);
        data[0] = 4;

        auto msg = parse_message(data);
        REQUIRE(msg.has_value());
        REQUIRE(std::holds_alternative<TransportData>(*msg));
    }
}
