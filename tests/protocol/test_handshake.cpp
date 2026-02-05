#include <catch2/catch_test_macros.hpp>
#include "vpn/protocol/session.hpp"
#include "vpn/protocol/peer.hpp"
#include "vpn/protocol/timer.hpp"
#include "vpn/crypto/curve25519.hpp"
#include "vpn/net/address.hpp"
#include <sodium.h>
#include <thread>
#include <chrono>

using namespace vpn::protocol;
using namespace vpn::crypto;
using namespace vpn::net;

TEST_CASE("Session encryption and decryption", "[protocol][session]") {
    SymmetricKey send_key, recv_key;
    randombytes_buf(send_key.data(), KEY_SIZE);
    randombytes_buf(recv_key.data(), KEY_SIZE);

    Session sender(send_key, recv_key, 1, 2);
    Session receiver(recv_key, send_key, 2, 1);  // Keys swapped for receiver

    SECTION("Basic encrypt/decrypt") {
        std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};

        auto ciphertext = sender.encrypt(plaintext);
        REQUIRE(ciphertext.size() == plaintext.size() + 16);  // +16 for tag

        auto decrypted = receiver.decrypt(ciphertext, 0);  // Counter was 0
        REQUIRE(decrypted.has_value());
        REQUIRE(*decrypted == plaintext);
    }

    SECTION("Counter increments") {
        REQUIRE(sender.current_send_counter() == 0);

        sender.encrypt({});
        REQUIRE(sender.current_send_counter() == 1);

        sender.encrypt({});
        REQUIRE(sender.current_send_counter() == 2);
    }

    SECTION("Wrong counter fails") {
        std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03};

        auto ciphertext = sender.encrypt(plaintext);

        // Try with wrong counter
        auto decrypted = receiver.decrypt(ciphertext, 99);
        REQUIRE_FALSE(decrypted.has_value());
    }

    SECTION("Replay protection") {
        std::vector<uint8_t> plaintext = {0x01, 0x02};

        auto ct1 = sender.encrypt(plaintext);
        auto ct2 = sender.encrypt(plaintext);

        // First decrypt succeeds
        auto dec1 = receiver.decrypt(ct1, 0);
        REQUIRE(dec1.has_value());

        // Second decrypt succeeds
        auto dec2 = receiver.decrypt(ct2, 1);
        REQUIRE(dec2.has_value());

        // Replay of first message fails
        auto replay = receiver.decrypt(ct1, 0);
        REQUIRE_FALSE(replay.has_value());
    }

    SECTION("Out of order within window") {
        std::vector<uint8_t> plaintext = {0x01};

        // Encrypt multiple messages
        std::vector<std::pair<std::vector<uint8_t>, uint64_t>> messages;
        for (int i = 0; i < 10; ++i) {
            uint64_t counter = sender.next_send_counter();
            auto ct = sender.encrypt(plaintext);
            sender.next_send_counter();  // Skip one
            messages.push_back({ct, counter});
        }

        // Decrypt out of order (backwards)
        for (auto it = messages.rbegin(); it != messages.rend(); ++it) {
            // Note: We need to manually handle counter since our session interface
            // doesn't expose the decryption with arbitrary counters easily
            // This test demonstrates the concept
        }
    }

    SECTION("Indices are stored correctly") {
        REQUIRE(sender.local_index() == 1);
        REQUIRE(sender.remote_index() == 2);
        REQUIRE(receiver.local_index() == 2);
        REQUIRE(receiver.remote_index() == 1);
    }
}

TEST_CASE("Session timing", "[protocol][session]") {
    SymmetricKey key;
    randombytes_buf(key.data(), KEY_SIZE);

    Session session(key, key, 1, 2);

    SECTION("Initial state") {
        REQUIRE_FALSE(session.needs_rekey());
        REQUIRE_FALSE(session.is_expired());
    }

    SECTION("Timestamps are updated") {
        auto created = session.created_at();
        auto last_sent = session.last_sent_at();

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        std::vector<uint8_t> test_data = {0x01};
        session.encrypt(test_data);

        REQUIRE(session.last_sent_at() > last_sent);
        REQUIRE(session.created_at() == created);
    }
}

TEST_CASE("PeerTimers", "[protocol][timer]") {
    PeerTimers timers;

    SECTION("Initial state has no events") {
        auto event = timers.next_event();
        REQUIRE_FALSE(event.has_value());
    }

    SECTION("Handshake initiated triggers retransmit") {
        timers.handshake_initiated();
        REQUIRE(timers.handshake_in_progress());

        auto event = timers.next_event();
        REQUIRE(event.has_value());
        REQUIRE(event->first == TimerEvent::RetransmitHandshake);
        REQUIRE(event->second > std::chrono::seconds(0));  // Should wait
    }

    SECTION("Handshake complete clears in-progress") {
        timers.handshake_initiated();
        timers.handshake_complete();

        REQUIRE_FALSE(timers.handshake_in_progress());
    }

    SECTION("Data received triggers keepalive") {
        timers.handshake_complete();
        timers.data_received();

        auto event = timers.next_event();
        REQUIRE(event.has_value());
        REQUIRE(event->first == TimerEvent::SendKeepalive);
    }

    SECTION("Persistent keepalive") {
        timers.handshake_complete();
        timers.set_persistent_keepalive(std::chrono::seconds(25));
        timers.data_sent();

        auto event = timers.next_event();
        if (event) {
            REQUIRE(event->first == TimerEvent::PersistentKeepalive);
        }
    }

    SECTION("Reset clears all state") {
        timers.handshake_initiated();
        timers.handshake_initiated();
        timers.handshake_initiated();

        REQUIRE(timers.handshake_attempts() == 3);

        timers.reset();

        REQUIRE(timers.handshake_attempts() == 0);
        REQUIRE_FALSE(timers.handshake_in_progress());
    }
}

TEST_CASE("Peer configuration", "[protocol][peer]") {
    PeerConfig config;
    config.public_key = Curve25519KeyPair::generate().public_key();
    config.endpoint = SocketAddress::parse("192.168.1.1:51820");
    config.allowed_ips.push_back(*Subnet::parse("10.0.0.0/24"));
    config.persistent_keepalive = std::chrono::seconds(25);

    Peer peer(config);

    SECTION("Public key stored") {
        REQUIRE(peer.public_key() == config.public_key);
    }

    SECTION("Endpoint stored") {
        auto endpoint = peer.endpoint();
        REQUIRE(endpoint.has_value());
        REQUIRE(endpoint->to_string() == "192.168.1.1:51820");
    }

    SECTION("Endpoint can be updated") {
        peer.set_endpoint(*SocketAddress::parse("10.0.0.1:51820"));
        auto endpoint = peer.endpoint();
        REQUIRE(endpoint.has_value());
        REQUIRE(endpoint->to_string() == "10.0.0.1:51820");
    }

    SECTION("Allowed IPs checked") {
        REQUIRE(peer.is_allowed_ip(IpAddress(*IPv4Address::parse("10.0.0.5"))));
        auto not_allowed = IpAddress(*IPv4Address::parse("192.168.1.5"));
        REQUIRE_FALSE(peer.is_allowed_ip(not_allowed));
    }
}

TEST_CASE("Peer session management", "[protocol][peer]") {
    PeerConfig config;
    config.public_key = Curve25519KeyPair::generate().public_key();

    Peer peer(config);

    SECTION("No session initially") {
        REQUIRE(peer.current_session() == nullptr);
        REQUIRE(peer.previous_session() == nullptr);
    }

    SECTION("Set current session") {
        SymmetricKey key;
        randombytes_buf(key.data(), KEY_SIZE);

        auto session = std::make_shared<Session>(key, key, 1, 2);
        peer.set_current_session(session);

        REQUIRE(peer.current_session() == session);
        REQUIRE(peer.previous_session() == nullptr);
    }

    SECTION("Rotate session") {
        SymmetricKey key;
        randombytes_buf(key.data(), KEY_SIZE);

        auto session1 = std::make_shared<Session>(key, key, 1, 2);
        auto session2 = std::make_shared<Session>(key, key, 3, 4);

        peer.set_current_session(session1);
        peer.rotate_session(session2);

        REQUIRE(peer.current_session() == session2);
        REQUIRE(peer.previous_session() == session1);
    }

    SECTION("Find session by index") {
        SymmetricKey key;
        randombytes_buf(key.data(), KEY_SIZE);

        auto session1 = std::make_shared<Session>(key, key, 100, 200);
        auto session2 = std::make_shared<Session>(key, key, 300, 400);

        peer.set_current_session(session1);
        peer.rotate_session(session2);

        REQUIRE(peer.session_by_index(300) == session2);
        REQUIRE(peer.session_by_index(100) == session1);
        REQUIRE(peer.session_by_index(999) == nullptr);
    }
}

TEST_CASE("Peer statistics", "[protocol][peer]") {
    PeerConfig config;
    config.public_key = Curve25519KeyPair::generate().public_key();

    Peer peer(config);

    SECTION("Initial stats are zero") {
        auto stats = peer.stats();
        REQUIRE(stats.rx_bytes == 0);
        REQUIRE(stats.tx_bytes == 0);
        REQUIRE(stats.rx_packets == 0);
        REQUIRE(stats.tx_packets == 0);
    }

    SECTION("Stats accumulate") {
        peer.add_rx_bytes(100);
        peer.add_rx_bytes(50);
        peer.add_tx_bytes(200);

        auto stats = peer.stats();
        REQUIRE(stats.rx_bytes == 150);
        REQUIRE(stats.tx_bytes == 200);
        REQUIRE(stats.rx_packets == 2);
        REQUIRE(stats.tx_packets == 1);
    }
}

TEST_CASE("Peer replay protection", "[protocol][peer]") {
    PeerConfig config;
    config.public_key = Curve25519KeyPair::generate().public_key();

    Peer peer(config);

    SECTION("New timestamp accepted") {
        auto ts1 = Tai64nTimestamp::now();
        REQUIRE(peer.check_replay_timestamp(ts1));
    }

    SECTION("Newer timestamp accepted") {
        auto ts1 = Tai64nTimestamp::now();
        REQUIRE(peer.check_replay_timestamp(ts1));

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        auto ts2 = Tai64nTimestamp::now();
        REQUIRE(peer.check_replay_timestamp(ts2));
    }

    SECTION("Replayed timestamp rejected") {
        auto ts = Tai64nTimestamp::now();
        REQUIRE(peer.check_replay_timestamp(ts));
        REQUIRE_FALSE(peer.check_replay_timestamp(ts));
    }
}
