#include "vpn/crypto/noise.hpp"
#include "vpn/crypto/blake2s.hpp"
#include "vpn/crypto/chacha20poly1305.hpp"
#include <sodium.h>
#include <cstring>
#include <chrono>

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

uint32_t generate_index() {
    uint32_t index;
    randombytes_buf(&index, sizeof(index));
    return index;
}

} // anonymous namespace

// Tai64nTimestamp implementation

Tai64nTimestamp Tai64nTimestamp::now() {
    Tai64nTimestamp ts;

    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch).count();
    auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(epoch).count() % 1000000000;

    // TAI64N: 8 bytes seconds (with 2^62 offset) + 4 bytes nanoseconds
    uint64_t tai_seconds = static_cast<uint64_t>(seconds) + 4611686018427387914ULL;

    // Big-endian encoding
    for (size_t i = 0; i < 8; ++i) {
        ts.bytes[i] = static_cast<uint8_t>((tai_seconds >> (8 * (7 - i))) & 0xFF);
    }
    for (size_t i = 0; i < 4; ++i) {
        ts.bytes[8 + i] = static_cast<uint8_t>((nanos >> (8 * (3 - i))) & 0xFF);
    }

    return ts;
}

bool Tai64nTimestamp::operator>(const Tai64nTimestamp& other) const {
    return std::memcmp(bytes.data(), other.bytes.data(), SIZE) > 0;
}

// NoiseHandshake implementation

NoiseHandshake NoiseHandshake::create_initiator(
    const Curve25519KeyPair& local_static,
    const PublicKey& remote_static,
    const PresharedKey& psk
) {
    ensure_sodium_initialized();

    NoiseHandshake hs;
    hs.role_ = Role::Initiator;
    hs.state_ = State::Initial;
    hs.local_static_ = local_static;
    hs.remote_static_ = remote_static;
    hs.psk_ = psk;

    // Initialize protocol state
    // h = HASH(CONSTRUCTION)
    hs.hash_ = construction_hash();
    // ck = h
    std::memcpy(hs.chaining_key_.data(), hs.hash_.data(), KEY_SIZE);
    // h = HASH(h || identifier)
    hs.hash_ = vpn::crypto::mix_hash(hs.hash_, {reinterpret_cast<const uint8_t*>(WG_IDENTIFIER.data()),
                                   WG_IDENTIFIER.size()});
    // h = HASH(h || remote_static)
    hs.hash_ = vpn::crypto::mix_hash(hs.hash_, {remote_static.data(), KEY_SIZE});

    return hs;
}

NoiseHandshake NoiseHandshake::create_responder(
    const Curve25519KeyPair& local_static,
    const PresharedKey& psk
) {
    ensure_sodium_initialized();

    NoiseHandshake hs;
    hs.role_ = Role::Responder;
    hs.state_ = State::WaitingForInitiation;
    hs.local_static_ = local_static;
    hs.psk_ = psk;

    // Initialize protocol state
    hs.hash_ = construction_hash();
    std::memcpy(hs.chaining_key_.data(), hs.hash_.data(), KEY_SIZE);
    hs.hash_ = vpn::crypto::mix_hash(hs.hash_, {reinterpret_cast<const uint8_t*>(WG_IDENTIFIER.data()),
                                   WG_IDENTIFIER.size()});
    // For responder, h = HASH(h || local_static)
    hs.hash_ = vpn::crypto::mix_hash(hs.hash_, {local_static.public_key().data(), KEY_SIZE});

    return hs;
}

void NoiseHandshake::mix_hash(std::span<const uint8_t> data) {
    hash_ = vpn::crypto::mix_hash(hash_, data);
}

void NoiseHandshake::mix_key(std::span<const uint8_t> input_key_material) {
    auto result = vpn::crypto::mix_key(
        reinterpret_cast<const SymmetricKey&>(chaining_key_),
        input_key_material
    );
    std::memcpy(chaining_key_.data(), result.chaining_key.data(), KEY_SIZE);
    encryption_key_ = std::move(result.output_key);
}

std::vector<uint8_t> NoiseHandshake::encrypt_and_hash(std::span<const uint8_t> plaintext) {
    if (!encryption_key_) {
        throw std::runtime_error("No encryption key available");
    }

    ChaCha20Poly1305 cipher(*encryption_key_);
    auto ciphertext = cipher.encrypt(plaintext, {hash_.data(), HASH_SIZE}, 0);
    mix_hash(ciphertext);
    return ciphertext;
}

std::optional<std::vector<uint8_t>> NoiseHandshake::decrypt_and_hash(std::span<const uint8_t> ciphertext) {
    if (!encryption_key_) {
        return std::nullopt;
    }

    ChaCha20Poly1305 cipher(*encryption_key_);
    auto plaintext = cipher.decrypt(ciphertext, {hash_.data(), HASH_SIZE}, 0);
    if (!plaintext) {
        return std::nullopt;
    }
    mix_hash(ciphertext);
    return plaintext;
}

std::optional<NoiseHandshake::InitiationResult> NoiseHandshake::create_initiation() {
    if (role_ != Role::Initiator || state_ != State::Initial) {
        return std::nullopt;
    }

    // Generate ephemeral key pair
    local_ephemeral_ = Curve25519KeyPair::generate();

    // Message format:
    // type (1) + reserved (3) + sender_index (4) + ephemeral (32) +
    // encrypted_static (32+16) + encrypted_timestamp (12+16) + mac1 (16) + mac2 (16)
    // Total: 148 bytes

    std::vector<uint8_t> message(148, 0);

    // Type = 1 (handshake initiation)
    message[0] = 0x01;

    // Sender index
    local_index_ = generate_index();
    std::memcpy(&message[4], &local_index_, 4);

    // e = ephemeral public key
    std::memcpy(&message[8], local_ephemeral_->public_key().data(), KEY_SIZE);
    mix_hash({local_ephemeral_->public_key().data(), KEY_SIZE});

    // ck, k = KDF(ck, DH(e, rs))
    auto dh_result = x25519(local_ephemeral_->private_key(), *remote_static_);
    mix_key({dh_result.data(), KEY_SIZE});

    // encrypted_static = AEAD(k, 0, static_public, h)
    auto encrypted_static = encrypt_and_hash({local_static_.public_key().data(), KEY_SIZE});
    std::memcpy(&message[40], encrypted_static.data(), encrypted_static.size());

    // ck, k = KDF(ck, DH(s, rs))
    auto dh_static = x25519(local_static_.private_key(), *remote_static_);
    mix_key({dh_static.data(), KEY_SIZE});

    // encrypted_timestamp = AEAD(k, 0, timestamp, h)
    timestamp_ = Tai64nTimestamp::now();
    auto encrypted_timestamp = encrypt_and_hash({timestamp_->bytes.data(), Tai64nTimestamp::SIZE});
    std::memcpy(&message[88], encrypted_timestamp.data(), encrypted_timestamp.size());

    // MAC1 = HASH(LABEL_MAC1 || remote_static)[:16] as key, msg[:116]
    auto mac1 = compute_mac1(*remote_static_, {message.data(), 116});
    std::memcpy(&message[116], mac1.data(), 16);

    // MAC2 = 0 (no cookie yet)
    // Already zeroed

    state_ = State::WaitingForResponse;
    return InitiationResult{std::move(message), local_index_};
}

std::optional<NoiseHandshake::ResponseResult> NoiseHandshake::process_initiation(
    std::span<const uint8_t> initiation
) {
    if (role_ != Role::Responder || state_ != State::WaitingForInitiation) {
        return std::nullopt;
    }

    if (initiation.size() != 148) {
        return std::nullopt;
    }

    // Verify type
    if (initiation[0] != 0x01) {
        return std::nullopt;
    }

    // Extract sender index
    std::memcpy(&remote_index_, &initiation[4], 4);

    // Extract ephemeral public key
    PublicKey remote_ephemeral;
    std::memcpy(remote_ephemeral.data(), &initiation[8], KEY_SIZE);
    remote_ephemeral_ = remote_ephemeral;
    mix_hash({remote_ephemeral.data(), KEY_SIZE});

    // ck, k = KDF(ck, DH(s, re))
    auto dh_result = x25519(local_static_.private_key(), remote_ephemeral);
    mix_key({dh_result.data(), KEY_SIZE});

    // Decrypt static key
    auto decrypted_static = decrypt_and_hash({&initiation[40], 48});
    if (!decrypted_static || decrypted_static->size() != KEY_SIZE) {
        state_ = State::Failed;
        return std::nullopt;
    }

    PublicKey initiator_static;
    std::memcpy(initiator_static.data(), decrypted_static->data(), KEY_SIZE);
    remote_static_ = initiator_static;

    // ck, k = KDF(ck, DH(s, rs))
    auto dh_static = x25519(local_static_.private_key(), initiator_static);
    mix_key({dh_static.data(), KEY_SIZE});

    // Decrypt timestamp
    auto decrypted_timestamp = decrypt_and_hash({&initiation[88], 28});
    if (!decrypted_timestamp || decrypted_timestamp->size() != Tai64nTimestamp::SIZE) {
        state_ = State::Failed;
        return std::nullopt;
    }

    Tai64nTimestamp ts;
    std::memcpy(ts.bytes.data(), decrypted_timestamp->data(), Tai64nTimestamp::SIZE);
    timestamp_ = ts;

    // Verify MAC1 (MAC2 verification would require cookie state)
    auto expected_mac1 = compute_mac1(local_static_.public_key(), {initiation.data(), 116});
    if (std::memcmp(&initiation[116], expected_mac1.data(), 16) != 0) {
        state_ = State::Failed;
        return std::nullopt;
    }

    // Create response
    // Generate our ephemeral key
    local_ephemeral_ = Curve25519KeyPair::generate();
    local_index_ = generate_index();

    // Response format:
    // type (1) + reserved (3) + sender_index (4) + receiver_index (4) +
    // ephemeral (32) + encrypted_nothing (0+16) + mac1 (16) + mac2 (16)
    // Total: 92 bytes

    std::vector<uint8_t> response(92, 0);

    // Type = 2 (handshake response)
    response[0] = 0x02;

    // Sender index (our index)
    std::memcpy(&response[4], &local_index_, 4);

    // Receiver index (initiator's index)
    std::memcpy(&response[8], &remote_index_, 4);

    // e = our ephemeral
    std::memcpy(&response[12], local_ephemeral_->public_key().data(), KEY_SIZE);
    mix_hash({local_ephemeral_->public_key().data(), KEY_SIZE});

    // ck, k = KDF(ck, DH(e, re))
    auto dh_ee = x25519(local_ephemeral_->private_key(), *remote_ephemeral_);
    mix_key({dh_ee.data(), KEY_SIZE});

    // ck, k = KDF(ck, DH(e, rs))
    auto dh_es = x25519(local_ephemeral_->private_key(), *remote_static_);
    mix_key({dh_es.data(), KEY_SIZE});

    // ck, k = KDF(ck, psk)
    mix_key({psk_.data(), KEY_SIZE});

    // encrypted_nothing = AEAD(k, 0, empty, h)
    auto encrypted_nothing = encrypt_and_hash({});
    std::memcpy(&response[44], encrypted_nothing.data(), encrypted_nothing.size());

    // MAC1
    auto mac1 = compute_mac1(*remote_static_, {response.data(), 60});
    std::memcpy(&response[60], mac1.data(), 16);

    // MAC2 = 0

    // Derive session keys
    auto keys = hkdf<2>({chaining_key_.data(), KEY_SIZE}, {});

    session_keys_ = SessionKeys{
        std::move(keys[0]),  // send_key (responder sends first)
        std::move(keys[1]),  // receive_key
        local_index_,
        remote_index_
    };

    state_ = State::Established;

    return ResponseResult{
        std::move(response),
        local_index_,
        remote_index_,
        initiator_static
    };
}

std::optional<SessionKeys> NoiseHandshake::process_response(std::span<const uint8_t> response) {
    if (role_ != Role::Initiator || state_ != State::WaitingForResponse) {
        return std::nullopt;
    }

    if (response.size() != 92) {
        return std::nullopt;
    }

    // Verify type
    if (response[0] != 0x02) {
        return std::nullopt;
    }

    // Extract indices
    uint32_t sender_index, receiver_index;
    std::memcpy(&sender_index, &response[4], 4);
    std::memcpy(&receiver_index, &response[8], 4);

    if (receiver_index != local_index_) {
        return std::nullopt;
    }

    remote_index_ = sender_index;

    // Extract ephemeral
    PublicKey remote_ephemeral;
    std::memcpy(remote_ephemeral.data(), &response[12], KEY_SIZE);
    remote_ephemeral_ = remote_ephemeral;
    mix_hash({remote_ephemeral.data(), KEY_SIZE});

    // ck, k = KDF(ck, DH(e, re))
    auto dh_ee = x25519(local_ephemeral_->private_key(), remote_ephemeral);
    mix_key({dh_ee.data(), KEY_SIZE});

    // ck, k = KDF(ck, DH(s, re))
    auto dh_se = x25519(local_static_.private_key(), remote_ephemeral);
    mix_key({dh_se.data(), KEY_SIZE});

    // ck, k = KDF(ck, psk)
    mix_key({psk_.data(), KEY_SIZE});

    // Decrypt empty
    auto decrypted = decrypt_and_hash({&response[44], 16});
    if (!decrypted || !decrypted->empty()) {
        state_ = State::Failed;
        return std::nullopt;
    }

    // Verify MAC1
    auto expected_mac1 = compute_mac1(local_static_.public_key(), {response.data(), 60});
    if (std::memcmp(&response[60], expected_mac1.data(), 16) != 0) {
        state_ = State::Failed;
        return std::nullopt;
    }

    // Derive session keys (note: reversed for initiator)
    auto keys = hkdf<2>({chaining_key_.data(), KEY_SIZE}, {});

    session_keys_ = SessionKeys{
        std::move(keys[1]),  // send_key (initiator's send = responder's receive)
        std::move(keys[0]),  // receive_key
        local_index_,
        remote_index_
    };

    state_ = State::Established;
    return session_keys_;
}

std::optional<SessionKeys> NoiseHandshake::finalize() {
    if (state_ != State::Established || !session_keys_) {
        return std::nullopt;
    }
    return session_keys_;
}

// CookieGenerator implementation

CookieGenerator::CookieGenerator(const PublicKey& server_public_key) {
    ensure_sodium_initialized();

    randombytes_buf(secret_.data(), KEY_SIZE);
    randombytes_buf(prev_secret_.data(), KEY_SIZE);
    last_rotation_ = std::chrono::steady_clock::now();

    // Derive MAC1 key
    std::vector<uint8_t> label_key(WG_LABEL_MAC1.size() + KEY_SIZE);
    std::memcpy(label_key.data(), WG_LABEL_MAC1.data(), WG_LABEL_MAC1.size());
    std::memcpy(label_key.data() + WG_LABEL_MAC1.size(), server_public_key.data(), KEY_SIZE);
    mac1_key_ = blake2s(label_key);
}

std::array<uint8_t, 16> CookieGenerator::generate_cookie(
    std::span<const uint8_t> source_addr,
    const PublicKey& peer_public_key
) {
    std::vector<uint8_t> data(source_addr.size() + KEY_SIZE);
    std::memcpy(data.data(), source_addr.data(), source_addr.size());
    std::memcpy(data.data() + source_addr.size(), peer_public_key.data(), KEY_SIZE);

    auto hash = blake2s_keyed({secret_.data(), KEY_SIZE}, data);

    std::array<uint8_t, 16> cookie;
    std::memcpy(cookie.data(), hash.data(), 16);
    return cookie;
}

bool CookieGenerator::validate_cookie(
    std::span<const uint8_t, 16> cookie,
    std::span<const uint8_t> source_addr,
    const PublicKey& peer_public_key
) {
    auto expected = generate_cookie(source_addr, peer_public_key);
    if (std::memcmp(cookie.data(), expected.data(), 16) == 0) {
        return true;
    }

    // Try previous secret
    std::vector<uint8_t> data(source_addr.size() + KEY_SIZE);
    std::memcpy(data.data(), source_addr.data(), source_addr.size());
    std::memcpy(data.data() + source_addr.size(), peer_public_key.data(), KEY_SIZE);

    auto prev_hash = blake2s_keyed({prev_secret_.data(), KEY_SIZE}, data);
    return std::memcmp(cookie.data(), prev_hash.data(), 16) == 0;
}

void CookieGenerator::rotate_secret() {
    std::memcpy(prev_secret_.data(), secret_.data(), KEY_SIZE);
    randombytes_buf(secret_.data(), KEY_SIZE);
    last_rotation_ = std::chrono::steady_clock::now();
}

// MAC computation functions

std::array<uint8_t, 16> compute_mac1(
    const PublicKey& receiver_public_key,
    std::span<const uint8_t> message_without_macs
) {
    // key = HASH(LABEL_MAC1 || receiver_public_key)
    std::vector<uint8_t> key_input(WG_LABEL_MAC1.size() + KEY_SIZE);
    std::memcpy(key_input.data(), WG_LABEL_MAC1.data(), WG_LABEL_MAC1.size());
    std::memcpy(key_input.data() + WG_LABEL_MAC1.size(), receiver_public_key.data(), KEY_SIZE);
    auto key = blake2s(key_input);

    // mac1 = MAC(key, message)[:16]
    auto mac = blake2s_keyed({key.data(), KEY_SIZE}, message_without_macs);

    std::array<uint8_t, 16> result;
    std::memcpy(result.data(), mac.data(), 16);
    return result;
}

std::array<uint8_t, 16> compute_mac2(
    std::span<const uint8_t, 16> cookie,
    std::span<const uint8_t> message_without_mac2
) {
    auto mac = blake2s_keyed(cookie, message_without_mac2);

    std::array<uint8_t, 16> result;
    std::memcpy(result.data(), mac.data(), 16);
    return result;
}

} // namespace vpn::crypto
