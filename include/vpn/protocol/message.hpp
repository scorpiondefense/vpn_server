#pragma once

#include <cstdint>
#include <span>
#include <variant>
#include <optional>
#include <vector>
#include <array>

namespace vpn::protocol {

// WireGuard message types
enum class MessageType : uint8_t {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    CookieReply = 3,
    TransportData = 4
};

// Message sizes
inline constexpr size_t HANDSHAKE_INITIATION_SIZE = 148;
inline constexpr size_t HANDSHAKE_RESPONSE_SIZE = 92;
inline constexpr size_t COOKIE_REPLY_SIZE = 64;
inline constexpr size_t TRANSPORT_HEADER_SIZE = 16;

// Minimum packet size
inline constexpr size_t MIN_PACKET_SIZE = 4;

// Handshake initiation message (Type 1)
struct HandshakeInitiation {
    uint32_t sender_index;
    std::array<uint8_t, 32> ephemeral;
    std::array<uint8_t, 48> encrypted_static;     // 32 + 16 tag
    std::array<uint8_t, 28> encrypted_timestamp;  // 12 + 16 tag
    std::array<uint8_t, 16> mac1;
    std::array<uint8_t, 16> mac2;

    static std::optional<HandshakeInitiation> parse(std::span<const uint8_t> data);
    std::vector<uint8_t> serialize() const;
};

// Handshake response message (Type 2)
struct HandshakeResponse {
    uint32_t sender_index;
    uint32_t receiver_index;
    std::array<uint8_t, 32> ephemeral;
    std::array<uint8_t, 16> encrypted_nothing;  // 0 + 16 tag
    std::array<uint8_t, 16> mac1;
    std::array<uint8_t, 16> mac2;

    static std::optional<HandshakeResponse> parse(std::span<const uint8_t> data);
    std::vector<uint8_t> serialize() const;
};

// Cookie reply message (Type 3)
struct CookieReply {
    uint32_t receiver_index;
    std::array<uint8_t, 24> nonce;
    std::array<uint8_t, 32> encrypted_cookie;  // 16 + 16 tag

    static std::optional<CookieReply> parse(std::span<const uint8_t> data);
    std::vector<uint8_t> serialize() const;
};

// Transport data message (Type 4)
struct TransportData {
    uint32_t receiver_index;
    uint64_t counter;
    std::vector<uint8_t> encrypted_packet;  // Variable length, includes tag

    static std::optional<TransportData> parse(std::span<const uint8_t> data);
    std::vector<uint8_t> serialize() const;

    // Build header for in-place encryption
    static void write_header(std::span<uint8_t> buffer, uint32_t receiver_index, uint64_t counter);
};

// Variant for any message type
using Message = std::variant<
    HandshakeInitiation,
    HandshakeResponse,
    CookieReply,
    TransportData
>;

// Parse any WireGuard message
std::optional<Message> parse_message(std::span<const uint8_t> data);

// Get message type from raw data
std::optional<MessageType> get_message_type(std::span<const uint8_t> data);

} // namespace vpn::protocol
