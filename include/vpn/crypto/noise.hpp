#pragma once

#include "types.hpp"
#include "curve25519.hpp"
#include <optional>
#include <memory>
#include <chrono>

namespace vpn::crypto {

// Timestamp for TAI64N format (used in WireGuard handshake initiation)
struct Tai64nTimestamp {
    std::array<uint8_t, 12> bytes;

    static Tai64nTimestamp now();
    bool operator>(const Tai64nTimestamp& other) const;

    // For replay protection
    static constexpr size_t SIZE = 12;
};

// Session keys derived from completed handshake
struct SessionKeys {
    SymmetricKey send_key;      // Key for encrypting outgoing packets
    SymmetricKey receive_key;   // Key for decrypting incoming packets
    uint32_t sender_index;      // Our session index
    uint32_t receiver_index;    // Their session index
};

// Handshake state for Noise_IKpsk2 pattern
class NoiseHandshake {
public:
    enum class Role {
        Initiator,
        Responder
    };

    enum class State {
        Initial,
        WaitingForResponse,     // Initiator: sent initiation, waiting for response
        WaitingForInitiation,   // Responder: waiting for initiation
        Established,            // Handshake complete
        Failed
    };

    // Create initiator handshake
    static NoiseHandshake create_initiator(
        const Curve25519KeyPair& local_static,
        const PublicKey& remote_static,
        const PresharedKey& psk = {}
    );

    // Create responder handshake
    static NoiseHandshake create_responder(
        const Curve25519KeyPair& local_static,
        const PresharedKey& psk = {}
    );

    // Initiator: create handshake initiation message
    // Returns the message bytes and the sender index
    struct InitiationResult {
        std::vector<uint8_t> message;
        uint32_t sender_index;
    };
    std::optional<InitiationResult> create_initiation();

    // Responder: process handshake initiation and create response
    struct ResponseResult {
        std::vector<uint8_t> message;
        uint32_t sender_index;
        uint32_t receiver_index;  // Initiator's index from initiation
        PublicKey initiator_public_key;
    };
    std::optional<ResponseResult> process_initiation(std::span<const uint8_t> initiation);

    // Initiator: process handshake response and finalize
    std::optional<SessionKeys> process_response(std::span<const uint8_t> response);

    // Responder: finalize after sending response
    std::optional<SessionKeys> finalize();

    // Get current state
    State state() const { return state_; }

    // Get the remote static public key (available after processing initiation)
    const std::optional<PublicKey>& remote_static() const { return remote_static_; }

    // Get timestamp from initiation (for replay protection)
    const std::optional<Tai64nTimestamp>& timestamp() const { return timestamp_; }

private:
    NoiseHandshake() = default;

    void mix_hash(std::span<const uint8_t> data);
    void mix_key(std::span<const uint8_t> input_key_material);
    std::vector<uint8_t> encrypt_and_hash(std::span<const uint8_t> plaintext);
    std::optional<std::vector<uint8_t>> decrypt_and_hash(std::span<const uint8_t> ciphertext);

    Role role_;
    State state_ = State::Initial;

    // Local keys
    Curve25519KeyPair local_static_;
    std::optional<Curve25519KeyPair> local_ephemeral_;

    // Remote keys
    std::optional<PublicKey> remote_static_;
    std::optional<PublicKey> remote_ephemeral_;

    // Pre-shared key
    PresharedKey psk_;

    // Noise protocol state
    Hash chaining_key_;
    Hash hash_;
    std::optional<SymmetricKey> encryption_key_;

    // Session indices
    uint32_t local_index_ = 0;
    uint32_t remote_index_ = 0;

    // Timestamp for replay protection
    std::optional<Tai64nTimestamp> timestamp_;

    // Derived session keys
    std::optional<SessionKeys> session_keys_;
};

// Cookie handling for DoS protection
class CookieGenerator {
public:
    explicit CookieGenerator(const PublicKey& server_public_key);

    // Generate a cookie for a peer
    std::array<uint8_t, 16> generate_cookie(
        std::span<const uint8_t> source_addr,  // IP:port as bytes
        const PublicKey& peer_public_key
    );

    // Validate a received cookie
    bool validate_cookie(
        std::span<const uint8_t, 16> cookie,
        std::span<const uint8_t> source_addr,
        const PublicKey& peer_public_key
    );

    // Rotate the secret (should be called periodically)
    void rotate_secret();

private:
    SymmetricKey secret_;
    SymmetricKey prev_secret_;
    std::chrono::steady_clock::time_point last_rotation_;
    Hash mac1_key_;  // Derived from server public key
};

// MAC computation for handshake messages
std::array<uint8_t, 16> compute_mac1(
    const PublicKey& receiver_public_key,
    std::span<const uint8_t> message_without_macs
);

std::array<uint8_t, 16> compute_mac2(
    std::span<const uint8_t, 16> cookie,
    std::span<const uint8_t> message_without_mac2
);

} // namespace vpn::crypto
