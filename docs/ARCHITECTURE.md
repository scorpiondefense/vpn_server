# WireGuard VPN Server Architecture

This document explains how the WireGuard-compatible VPN server works, including the cryptographic protocols, handshake process, and packet flow.

## Table of Contents

- [Overview](#overview)
- [Cryptographic Primitives](#cryptographic-primitives)
- [Key Types](#key-types)
- [The Noise Protocol](#the-noise-protocol)
- [Handshake Process](#handshake-process)
- [Session Keys](#session-keys)
- [Packet Types](#packet-types)
- [Data Flow](#data-flow)
- [Timer System](#timer-system)
- [Server Architecture](#server-architecture)

---

## Overview

WireGuard is a modern VPN protocol that uses state-of-the-art cryptography. Our implementation follows the [WireGuard specification](https://www.wireguard.com/protocol/) and uses the **Noise_IKpsk2** handshake pattern.

```
┌─────────────────────────────────────────────────────────────────┐
│                      VPN Server Overview                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────┐         UDP/51820          ┌─────────┐           │
│   │  Client │◄─────────────────────────►│  Server │           │
│   │ (Peer)  │    Encrypted Tunnel        │         │           │
│   └────┬────┘                            └────┬────┘           │
│        │                                      │                 │
│        │  ┌──────────────────────────────┐   │                 │
│        └──┤  WireGuard Protocol Layer    ├───┘                 │
│           │  • Noise_IKpsk2 Handshake    │                     │
│           │  • ChaCha20-Poly1305 AEAD    │                     │
│           │  • Curve25519 Key Exchange   │                     │
│           └──────────────────────────────┘                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Cryptographic Primitives

WireGuard uses a carefully selected set of modern cryptographic primitives:

| Primitive | Algorithm | Purpose |
|-----------|-----------|---------|
| Key Exchange | Curve25519 (X25519) | Elliptic curve Diffie-Hellman |
| Encryption | ChaCha20-Poly1305 | Authenticated encryption (AEAD) |
| Hashing | BLAKE2s | Fast cryptographic hash |
| KDF | HKDF | Key derivation from shared secrets |
| Timestamps | TAI64N | Replay attack prevention |

```
┌─────────────────────────────────────────────────────────────────┐
│                   Cryptographic Stack                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Curve25519 │  │  ChaCha20   │  │   BLAKE2s   │             │
│  │   (X25519)  │  │  Poly1305   │  │             │             │
│  ├─────────────┤  ├─────────────┤  ├─────────────┤             │
│  │ 32-byte     │  │ 32-byte key │  │ 32-byte     │             │
│  │ public key  │  │ 12-byte     │  │ output      │             │
│  │ 32-byte     │  │ nonce       │  │             │             │
│  │ private key │  │ 16-byte tag │  │             │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│         │                │                │                     │
│         └────────────────┼────────────────┘                     │
│                          ▼                                      │
│              ┌─────────────────────┐                           │
│              │    Noise Protocol   │                           │
│              │    (IKpsk2 pattern) │                           │
│              └─────────────────────┘                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Types

The server manages several types of cryptographic keys:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Key Hierarchy                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STATIC KEYS (Long-term, configured)                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Server Static Key Pair                                  │   │
│  │  ├── Private Key (32 bytes) - SECRET, never transmitted  │   │
│  │  └── Public Key  (32 bytes) - Shared with clients        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Pre-Shared Key (Optional, 32 bytes)                     │   │
│  │  └── Provides post-quantum security layer                │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  EPHEMERAL KEYS (Per-handshake, temporary)                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Ephemeral Key Pair                                      │   │
│  │  ├── Generated fresh for each handshake                  │   │
│  │  └── Provides forward secrecy                            │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  SESSION KEYS (Derived, short-lived)                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Transport Keys                                          │   │
│  │  ├── Send Key    (32 bytes) - Encrypt outgoing packets   │   │
│  │  └── Receive Key (32 bytes) - Decrypt incoming packets   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## The Noise Protocol

WireGuard uses the **Noise_IKpsk2** pattern from the [Noise Protocol Framework](https://noiseprotocol.org/). The pattern name breaks down as:

- **I** - Initiator's static key is transmitted to responder
- **K** - Responder's static key is known to initiator beforehand
- **psk2** - Pre-shared key mixed in at handshake message 2

```
Noise_IKpsk2 Pattern:

    Initiator                              Responder
        |                                      |
        |  knows: responder's static public    |
        |                                      |
   (1)  |  -------- Handshake Init --------->  |
        |  e, es, s, ss                        |
        |                                      |
        |                                      |  (2)
        |  <------- Handshake Response ------  |
        |                        e, ee, se, psk|
        |                                      |
        |  ======= Encrypted Tunnel ========>  |
        |  <======= Encrypted Tunnel ========  |
        |                                      |

Legend:
  e   = ephemeral public key
  s   = static public key (encrypted)
  es  = DH(ephemeral, static)
  ee  = DH(ephemeral, ephemeral)
  ss  = DH(static, static)
  se  = DH(static, ephemeral)
  psk = pre-shared key mixing
```

---

## Handshake Process

### Message 1: Handshake Initiation (148 bytes)

The initiator (client) sends the first message to establish a connection.

```
┌─────────────────────────────────────────────────────────────────┐
│              Handshake Initiation Message (148 bytes)           │
├─────────┬───────────────────────────────────────────────────────┤
│ Offset  │ Field                                                 │
├─────────┼───────────────────────────────────────────────────────┤
│  0      │ Type (1 byte) = 0x01                                  │
│  1      │ Reserved (3 bytes) = 0x000000                         │
│  4      │ Sender Index (4 bytes) - random identifier            │
│  8      │ Ephemeral Public Key (32 bytes)                       │
│  40     │ Encrypted Static Key (48 bytes) - includes 16B tag    │
│  88     │ Encrypted Timestamp (28 bytes) - includes 16B tag     │
│  116    │ MAC1 (16 bytes) - keyed by responder's public key     │
│  132    │ MAC2 (16 bytes) - keyed by cookie (if under load)     │
└─────────┴───────────────────────────────────────────────────────┘

Construction:
  1. Generate ephemeral keypair (e_priv, e_pub)
  2. C = HASH("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
  3. H = HASH(C || "WireGuard v1 zx2c4 Jason@zx2c4.com")
  4. H = HASH(H || responder_static_public)
  5. C = KDF(C, e_pub)
  6. H = HASH(H || e_pub)
  7. (C, k) = KDF(C, DH(e_priv, responder_static))    # es
  8. encrypted_static = AEAD(k, 0, initiator_static_public, H)
  9. H = HASH(H || encrypted_static)
  10. (C, k) = KDF(C, DH(initiator_static_priv, responder_static)) # ss
  11. encrypted_timestamp = AEAD(k, 0, TAI64N_timestamp, H)
  12. H = HASH(H || encrypted_timestamp)
  13. MAC1 = MAC(HASH("mac1----" || responder_static), msg[0:116])
  14. MAC2 = MAC(cookie, msg[0:132]) or zeros
```

### Message 2: Handshake Response (92 bytes)

The responder (server) completes the handshake.

```
┌─────────────────────────────────────────────────────────────────┐
│              Handshake Response Message (92 bytes)              │
├─────────┬───────────────────────────────────────────────────────┤
│ Offset  │ Field                                                 │
├─────────┼───────────────────────────────────────────────────────┤
│  0      │ Type (1 byte) = 0x02                                  │
│  1      │ Reserved (3 bytes) = 0x000000                         │
│  4      │ Sender Index (4 bytes) - responder's identifier       │
│  8      │ Receiver Index (4 bytes) - from initiation message    │
│  12     │ Ephemeral Public Key (32 bytes)                       │
│  44     │ Encrypted Empty (16 bytes) - just the AEAD tag        │
│  60     │ MAC1 (16 bytes)                                       │
│  76     │ MAC2 (16 bytes)                                       │
└─────────┴───────────────────────────────────────────────────────┘

Construction:
  1. Generate ephemeral keypair (e_priv, e_pub)
  2. C = KDF(C, e_pub)
  3. H = HASH(H || e_pub)
  4. (C, k) = KDF(C, DH(e_priv, initiator_ephemeral))  # ee
  5. (C, k) = KDF(C, DH(e_priv, initiator_static))     # se
  6. (C, k) = KDF(C, preshared_key)                    # psk
  7. encrypted_nothing = AEAD(k, 0, "", H)
  8. H = HASH(H || encrypted_nothing)
  9. Derive transport keys from C
```

### Key Derivation After Handshake

```
┌─────────────────────────────────────────────────────────────────┐
│                 Session Key Derivation                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│    Chaining Key (C) after handshake                            │
│              │                                                  │
│              ▼                                                  │
│    ┌─────────────────┐                                         │
│    │  HKDF-Expand    │                                         │
│    │  (BLAKE2s)      │                                         │
│    └────────┬────────┘                                         │
│             │                                                   │
│      ┌──────┴──────┐                                           │
│      ▼             ▼                                            │
│  ┌───────┐    ┌───────┐                                        │
│  │ Key 1 │    │ Key 2 │                                        │
│  └───┬───┘    └───┬───┘                                        │
│      │            │                                             │
│      ▼            ▼                                             │
│  Initiator    Initiator                                        │
│  Send Key     Receive Key                                      │
│  (= Responder (= Responder                                     │
│   Recv Key)    Send Key)                                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Packet Types

WireGuard defines four message types:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Message Types                              │
├──────┬──────────────────────────┬───────────────────────────────┤
│ Type │ Name                     │ Size                          │
├──────┼──────────────────────────┼───────────────────────────────┤
│ 0x01 │ Handshake Initiation     │ 148 bytes                     │
│ 0x02 │ Handshake Response       │ 92 bytes                      │
│ 0x03 │ Cookie Reply             │ 64 bytes                      │
│ 0x04 │ Transport Data           │ 32 + payload + 16 bytes       │
└──────┴──────────────────────────┴───────────────────────────────┘
```

### Transport Data Packet

After handshake, all data flows through transport packets:

```
┌─────────────────────────────────────────────────────────────────┐
│                Transport Data Packet                            │
├─────────┬───────────────────────────────────────────────────────┤
│ Offset  │ Field                                                 │
├─────────┼───────────────────────────────────────────────────────┤
│  0      │ Type (1 byte) = 0x04                                  │
│  1      │ Reserved (3 bytes) = 0x000000                         │
│  4      │ Receiver Index (4 bytes)                              │
│  8      │ Counter (8 bytes) - little-endian nonce               │
│  16     │ Encrypted Payload (variable) + 16-byte auth tag       │
└─────────┴───────────────────────────────────────────────────────┘

Encryption:
  nonce = counter (padded to 12 bytes for ChaCha20-Poly1305)
  ciphertext = ChaCha20-Poly1305(key, nonce, plaintext, "")
```

### Cookie Reply (DoS Protection)

Under load, server can require cookie validation:

```
┌─────────────────────────────────────────────────────────────────┐
│                   Cookie Reply (64 bytes)                       │
├─────────┬───────────────────────────────────────────────────────┤
│  0      │ Type (1 byte) = 0x03                                  │
│  1      │ Reserved (3 bytes)                                    │
│  4      │ Receiver Index (4 bytes)                              │
│  8      │ Nonce (24 bytes) - XChaCha20-Poly1305 nonce           │
│  32     │ Encrypted Cookie (32 bytes) - 16B cookie + 16B tag    │
└─────────┴───────────────────────────────────────────────────────┘
```

---

## Data Flow

### Outbound Packet Flow (Server → Client)

```
┌─────────────────────────────────────────────────────────────────┐
│                  Outbound Packet Flow                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐                                                   │
│  │ Internet │                                                   │
│  └────┬─────┘                                                   │
│       │ IP Packet destined for VPN client                       │
│       ▼                                                         │
│  ┌──────────┐                                                   │
│  │   TUN    │  Read IP packet from tunnel interface             │
│  │ Device   │                                                   │
│  └────┬─────┘                                                   │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────────────┐                                           │
│  │ Route Lookup     │  Find peer by destination IP              │
│  │ (AllowedIPs)     │  in AllowedIPs table                      │
│  └────┬─────────────┘                                           │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────────────┐                                           │
│  │ Session Check    │  Has valid session? If not, queue         │
│  │                  │  packet and initiate handshake            │
│  └────┬─────────────┘                                           │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────────────┐                                           │
│  │ Encrypt          │  ChaCha20-Poly1305 with session key       │
│  │ (AEAD)           │  Counter incremented atomically           │
│  └────┬─────────────┘                                           │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────────────┐                                           │
│  │ Build Transport  │  Prepend header with receiver index       │
│  │ Packet           │  and counter                              │
│  └────┬─────────────┘                                           │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────┐                                                   │
│  │   UDP    │  Send to peer's endpoint                          │
│  │ Socket   │  (IP:51820)                                       │
│  └──────────┘                                                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Inbound Packet Flow (Client → Server)

```
┌─────────────────────────────────────────────────────────────────┐
│                   Inbound Packet Flow                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐                                                   │
│  │   UDP    │  Receive packet on port 51820                     │
│  │ Socket   │                                                   │
│  └────┬─────┘                                                   │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────────────┐                                           │
│  │ Parse Header     │  Check message type (1-4)                 │
│  │                  │                                           │
│  └────┬─────────────┘                                           │
│       │                                                         │
│       ├─── Type 1 ──► Handshake Initiation Handler              │
│       ├─── Type 2 ──► Handshake Response Handler                │
│       ├─── Type 3 ──► Cookie Reply Handler                      │
│       │                                                         │
│       └─── Type 4 ──► Transport Data Handler                    │
│                │                                                │
│                ▼                                                 │
│  ┌──────────────────┐                                           │
│  │ Session Lookup   │  Find session by receiver index           │
│  │                  │                                           │
│  └────┬─────────────┘                                           │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────────────┐                                           │
│  │ Replay Check     │  Verify counter not seen before           │
│  │ (Sliding Window) │  Window size: 8192 packets                │
│  └────┬─────────────┘                                           │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────────────┐                                           │
│  │ Decrypt          │  ChaCha20-Poly1305 with session key       │
│  │ (AEAD)           │  Verify authentication tag                │
│  └────┬─────────────┘                                           │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────────────┐                                           │
│  │ Validate Source  │  Check source IP against peer's           │
│  │ (AllowedIPs)     │  AllowedIPs (anti-spoofing)              │
│  └────┬─────────────┘                                           │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────┐                                                   │
│  │   TUN    │  Write decrypted IP packet to tunnel              │
│  │ Device   │                                                   │
│  └──────────┘                                                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Timer System

WireGuard uses several timers to maintain connections:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Timer Events                               │
├───────────────────────┬─────────────────────────────────────────┤
│ Timer                 │ Behavior                                │
├───────────────────────┼─────────────────────────────────────────┤
│ REKEY_AFTER_TIME      │ Initiate rekey after 120 seconds        │
│ (120 seconds)         │ of session activity                     │
├───────────────────────┼─────────────────────────────────────────┤
│ REJECT_AFTER_TIME     │ Reject session after 180 seconds        │
│ (180 seconds)         │ (force new handshake)                   │
├───────────────────────┼─────────────────────────────────────────┤
│ REKEY_TIMEOUT         │ Retry handshake if no response          │
│ (5 seconds)           │ after 5 seconds                         │
├───────────────────────┼─────────────────────────────────────────┤
│ KEEPALIVE_TIMEOUT     │ Send keepalive if no data sent          │
│ (10 seconds)          │ for 10 seconds after receiving          │
├───────────────────────┼─────────────────────────────────────────┤
│ PERSISTENT_KEEPALIVE  │ Send keepalive every N seconds          │
│ (configurable)        │ to maintain NAT mappings                │
└───────────────────────┴─────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                   Timer State Machine                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│                    ┌─────────────┐                              │
│                    │    IDLE     │                              │
│                    └──────┬──────┘                              │
│                           │ data to send                        │
│                           ▼                                     │
│                    ┌─────────────┐                              │
│      ┌─────────────│  HANDSHAKE  │◄────────────┐               │
│      │  timeout    │  INITIATING │   rekey     │               │
│      │  (retry)    └──────┬──────┘   needed    │               │
│      │                    │ response            │               │
│      ▼                    ▼                     │               │
│ ┌─────────┐        ┌─────────────┐             │               │
│ │  RETRY  │───────►│ ESTABLISHED │─────────────┘               │
│ │ (max 3) │  resp  └──────┬──────┘  after 120s                 │
│ └─────────┘               │                                     │
│      │                    │ 180s timeout                        │
│      │ max retries        ▼                                     │
│      ▼              ┌─────────────┐                             │
│ ┌─────────┐         │  EXPIRED    │                             │
│ │ FAILED  │         │ (need new   │                             │
│ └─────────┘         │  handshake) │                             │
│                     └─────────────┘                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Server Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Server Components                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                     Main Event Loop                       │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │  │
│  │  │ UDP Socket  │  │ TUN Device  │  │   Timers    │       │  │
│  │  │  (kqueue/   │  │  (kqueue/   │  │             │       │  │
│  │  │   epoll)    │  │   epoll)    │  │             │       │  │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘       │  │
│  │         │                │                │               │  │
│  │         └────────────────┼────────────────┘               │  │
│  │                          ▼                                │  │
│  │                   Event Dispatcher                        │  │
│  └───────────────────────────┬───────────────────────────────┘  │
│                              │                                   │
│         ┌────────────────────┼────────────────────┐             │
│         ▼                    ▼                    ▼              │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐     │
│  │   Worker    │      │   Worker    │      │   Worker    │     │
│  │  Thread 1   │      │  Thread 2   │      │  Thread N   │     │
│  └─────────────┘      └─────────────┘      └─────────────┘     │
│         │                    │                    │              │
│         └────────────────────┼────────────────────┘             │
│                              ▼                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Shared State                           │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │  │
│  │  │    Peer     │  │   Session   │  │   Routing   │       │  │
│  │  │   Table     │  │   Index     │  │    Table    │       │  │
│  │  │ (by pubkey) │  │ (by index)  │  │ (AllowedIPs)│       │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Thread Model

```
┌─────────────────────────────────────────────────────────────────┐
│                      Threading Model                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Main Thread                                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ • Accept UDP packets (non-blocking)                      │   │
│  │ • Read TUN packets (non-blocking)                        │   │
│  │ • Process timer events                                   │   │
│  │ • Dispatch work to thread pool                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                 Lock-Free Work Queue                     │   │
│  │  ┌────┬────┬────┬────┬────┬────┬────┬────┬────┬────┐   │   │
│  │  │ P1 │ P2 │ P3 │ P4 │ P5 │ P6 │ P7 │ P8 │ ...│    │   │   │
│  │  └────┴────┴────┴────┴────┴────┴────┴────┴────┴────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│              ┌───────────────┼───────────────┐                 │
│              ▼               ▼               ▼                  │
│  ┌────────────────┐ ┌────────────────┐ ┌────────────────┐      │
│  │ Worker Thread  │ │ Worker Thread  │ │ Worker Thread  │      │
│  │ • Decrypt      │ │ • Decrypt      │ │ • Decrypt      │      │
│  │ • Encrypt      │ │ • Encrypt      │ │ • Encrypt      │      │
│  │ • Handshake    │ │ • Handshake    │ │ • Handshake    │      │
│  └────────────────┘ └────────────────┘ └────────────────┘      │
│                                                                 │
│  CPU Cores: Workers typically = num_cpus - 1                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### AllowedIPs Routing

The server maintains a routing table for AllowedIPs:

```
┌─────────────────────────────────────────────────────────────────┐
│                   AllowedIPs Routing Table                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Implemented as a longest-prefix-match (LPM) table              │
│                                                                 │
│  Example Configuration:                                         │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Peer A: 10.0.0.2/32, 192.168.1.0/24                     │   │
│  │ Peer B: 10.0.0.3/32, 10.10.0.0/16                       │   │
│  │ Peer C: 10.0.0.4/32, 0.0.0.0/0 (default route)          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  Lookup for 192.168.1.50:                                       │
│    /32 match? No                                                │
│    /24 match? Yes → Peer A                                      │
│                                                                 │
│  Lookup for 8.8.8.8:                                            │
│    /32 match? No                                                │
│    /24 match? No                                                │
│    /16 match? No                                                │
│    /0  match? Yes → Peer C (default)                            │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Trie Structure (Simplified)                 │   │
│  │                                                          │   │
│  │                       [root]                             │   │
│  │                      /      \                            │   │
│  │                   [0]        [1]                         │   │
│  │                  /              \                        │   │
│  │             [00...]          [10...]                     │   │
│  │               │                 │                        │   │
│  │            10.x.x.x        192.x.x.x                     │   │
│  │               │                 │                        │   │
│  │           ┌───┴───┐         ┌───┴───┐                   │   │
│  │        Peer A  Peer B    Peer A   ...                   │   │
│  │                                                          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Properties

WireGuard provides strong security guarantees:

```
┌─────────────────────────────────────────────────────────────────┐
│                   Security Properties                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ✓ Forward Secrecy                                              │
│    New ephemeral keys per handshake; compromise of long-term    │
│    keys doesn't reveal past session data                        │
│                                                                 │
│  ✓ Identity Hiding                                              │
│    Initiator's identity encrypted with responder's public key   │
│    (though responder's public key must be known)                │
│                                                                 │
│  ✓ Replay Protection                                            │
│    • Handshake: TAI64N timestamps                               │
│    • Transport: Sliding window (8192 packets)                   │
│                                                                 │
│  ✓ DoS Mitigation                                               │
│    • Cookie mechanism under load                                │
│    • No state allocated before MAC1 verification                │
│                                                                 │
│  ✓ Key Rotation                                                 │
│    Automatic rekey every 120 seconds or 2^60 messages           │
│                                                                 │
│  ✓ Silence by Default                                           │
│    No response to invalid packets; minimal attack surface       │
│                                                                 │
│  ✓ Optional Post-Quantum Security                               │
│    Pre-shared key provides defense against quantum computers    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## References

- [WireGuard Protocol Specification](https://www.wireguard.com/protocol/)
- [Noise Protocol Framework](https://noiseprotocol.org/)
- [WireGuard Whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
- [libsodium Documentation](https://doc.libsodium.org/)
