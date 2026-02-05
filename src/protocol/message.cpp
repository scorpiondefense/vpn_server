#include "vpn/protocol/message.hpp"
#include <cstring>

namespace vpn::protocol {

namespace {

template<typename T>
T read_le(const uint8_t* data) {
    T result = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        result |= static_cast<T>(data[i]) << (8 * i);
    }
    return result;
}

template<typename T>
void write_le(uint8_t* data, T value) {
    for (size_t i = 0; i < sizeof(T); ++i) {
        data[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
    }
}

} // anonymous namespace

// HandshakeInitiation

std::optional<HandshakeInitiation> HandshakeInitiation::parse(std::span<const uint8_t> data) {
    if (data.size() != HANDSHAKE_INITIATION_SIZE) {
        return std::nullopt;
    }

    if (data[0] != static_cast<uint8_t>(MessageType::HandshakeInitiation)) {
        return std::nullopt;
    }

    HandshakeInitiation msg;
    msg.sender_index = read_le<uint32_t>(&data[4]);
    std::memcpy(msg.ephemeral.data(), &data[8], 32);
    std::memcpy(msg.encrypted_static.data(), &data[40], 48);
    std::memcpy(msg.encrypted_timestamp.data(), &data[88], 28);
    std::memcpy(msg.mac1.data(), &data[116], 16);
    std::memcpy(msg.mac2.data(), &data[132], 16);

    return msg;
}

std::vector<uint8_t> HandshakeInitiation::serialize() const {
    std::vector<uint8_t> data(HANDSHAKE_INITIATION_SIZE, 0);

    data[0] = static_cast<uint8_t>(MessageType::HandshakeInitiation);
    // Bytes 1-3 are reserved (zero)
    write_le(&data[4], sender_index);
    std::memcpy(&data[8], ephemeral.data(), 32);
    std::memcpy(&data[40], encrypted_static.data(), 48);
    std::memcpy(&data[88], encrypted_timestamp.data(), 28);
    std::memcpy(&data[116], mac1.data(), 16);
    std::memcpy(&data[132], mac2.data(), 16);

    return data;
}

// HandshakeResponse

std::optional<HandshakeResponse> HandshakeResponse::parse(std::span<const uint8_t> data) {
    if (data.size() != HANDSHAKE_RESPONSE_SIZE) {
        return std::nullopt;
    }

    if (data[0] != static_cast<uint8_t>(MessageType::HandshakeResponse)) {
        return std::nullopt;
    }

    HandshakeResponse msg;
    msg.sender_index = read_le<uint32_t>(&data[4]);
    msg.receiver_index = read_le<uint32_t>(&data[8]);
    std::memcpy(msg.ephemeral.data(), &data[12], 32);
    std::memcpy(msg.encrypted_nothing.data(), &data[44], 16);
    std::memcpy(msg.mac1.data(), &data[60], 16);
    std::memcpy(msg.mac2.data(), &data[76], 16);

    return msg;
}

std::vector<uint8_t> HandshakeResponse::serialize() const {
    std::vector<uint8_t> data(HANDSHAKE_RESPONSE_SIZE, 0);

    data[0] = static_cast<uint8_t>(MessageType::HandshakeResponse);
    // Bytes 1-3 are reserved (zero)
    write_le(&data[4], sender_index);
    write_le(&data[8], receiver_index);
    std::memcpy(&data[12], ephemeral.data(), 32);
    std::memcpy(&data[44], encrypted_nothing.data(), 16);
    std::memcpy(&data[60], mac1.data(), 16);
    std::memcpy(&data[76], mac2.data(), 16);

    return data;
}

// CookieReply

std::optional<CookieReply> CookieReply::parse(std::span<const uint8_t> data) {
    if (data.size() != COOKIE_REPLY_SIZE) {
        return std::nullopt;
    }

    if (data[0] != static_cast<uint8_t>(MessageType::CookieReply)) {
        return std::nullopt;
    }

    CookieReply msg;
    msg.receiver_index = read_le<uint32_t>(&data[4]);
    std::memcpy(msg.nonce.data(), &data[8], 24);
    std::memcpy(msg.encrypted_cookie.data(), &data[32], 32);

    return msg;
}

std::vector<uint8_t> CookieReply::serialize() const {
    std::vector<uint8_t> data(COOKIE_REPLY_SIZE, 0);

    data[0] = static_cast<uint8_t>(MessageType::CookieReply);
    // Bytes 1-3 are reserved (zero)
    write_le(&data[4], receiver_index);
    std::memcpy(&data[8], nonce.data(), 24);
    std::memcpy(&data[32], encrypted_cookie.data(), 32);

    return data;
}

// TransportData

std::optional<TransportData> TransportData::parse(std::span<const uint8_t> data) {
    if (data.size() < TRANSPORT_HEADER_SIZE) {
        return std::nullopt;
    }

    if (data[0] != static_cast<uint8_t>(MessageType::TransportData)) {
        return std::nullopt;
    }

    TransportData msg;
    msg.receiver_index = read_le<uint32_t>(&data[4]);
    msg.counter = read_le<uint64_t>(&data[8]);
    msg.encrypted_packet.assign(data.begin() + 16, data.end());

    return msg;
}

std::vector<uint8_t> TransportData::serialize() const {
    std::vector<uint8_t> data(TRANSPORT_HEADER_SIZE + encrypted_packet.size());

    data[0] = static_cast<uint8_t>(MessageType::TransportData);
    // Bytes 1-3 are reserved (zero)
    write_le(&data[4], receiver_index);
    write_le(&data[8], counter);
    std::memcpy(&data[16], encrypted_packet.data(), encrypted_packet.size());

    return data;
}

void TransportData::write_header(std::span<uint8_t> buffer, uint32_t receiver_index, uint64_t counter) {
    if (buffer.size() < TRANSPORT_HEADER_SIZE) return;

    buffer[0] = static_cast<uint8_t>(MessageType::TransportData);
    buffer[1] = 0;
    buffer[2] = 0;
    buffer[3] = 0;
    write_le(&buffer[4], receiver_index);
    write_le(&buffer[8], counter);
}

// Message parsing

std::optional<MessageType> get_message_type(std::span<const uint8_t> data) {
    if (data.size() < MIN_PACKET_SIZE) {
        return std::nullopt;
    }

    switch (data[0]) {
        case 1: return MessageType::HandshakeInitiation;
        case 2: return MessageType::HandshakeResponse;
        case 3: return MessageType::CookieReply;
        case 4: return MessageType::TransportData;
        default: return std::nullopt;
    }
}

std::optional<Message> parse_message(std::span<const uint8_t> data) {
    auto type = get_message_type(data);
    if (!type) return std::nullopt;

    switch (*type) {
        case MessageType::HandshakeInitiation:
            if (auto msg = HandshakeInitiation::parse(data)) {
                return *msg;
            }
            break;
        case MessageType::HandshakeResponse:
            if (auto msg = HandshakeResponse::parse(data)) {
                return *msg;
            }
            break;
        case MessageType::CookieReply:
            if (auto msg = CookieReply::parse(data)) {
                return *msg;
            }
            break;
        case MessageType::TransportData:
            if (auto msg = TransportData::parse(data)) {
                return *msg;
            }
            break;
    }

    return std::nullopt;
}

} // namespace vpn::protocol
