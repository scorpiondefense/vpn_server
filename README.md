# WireGuard-Compatible VPN Server

A C++20 implementation of a WireGuard-compatible VPN server, designed for deployment on Digital Ocean or any Linux server.

## Features

- Full WireGuard protocol implementation (Noise_IKpsk2)
- Dual-stack IPv4/IPv6 support
- Multi-threaded packet processing
- Compatible with native WireGuard clients (macOS, iOS, Android, Windows, Linux)
- libsodium-based cryptography (Curve25519, ChaCha20-Poly1305, BLAKE2s)

## Building

### Prerequisites

- CMake 3.20+
- C++20 compatible compiler (GCC 10+, Clang 12+, Apple Clang 13+)
- libsodium >= 1.0.18

#### macOS
```bash
brew install cmake libsodium
```

#### Ubuntu/Debian
```bash
sudo apt install cmake build-essential libsodium-dev pkg-config
```

### Compile

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Run Tests

```bash
cd build
ctest --output-on-failure
```

## Usage

### Generate Keys

```bash
# Generate server private key
./wg-keygen genkey > server.key

# Derive public key
./wg-keygen pubkey < server.key > server.pub

# Generate pre-shared key (optional)
./wg-keygen genpsk > preshared.key

# Generate both keys at once
./wg-keygen keypair
```

### Server Configuration

Create `/etc/wireguard/wg0.conf`:

```ini
[Interface]
PrivateKey = <server-private-key>
ListenPort = 51820
Address = 10.0.0.1/24, fd00:vpn::1/64

[Peer]
PublicKey = <client-public-key>
AllowedIPs = 10.0.0.2/32
```

### Run Server

```bash
sudo ./vpn_server /etc/wireguard/wg0.conf
```

### Client Configuration (for macOS WireGuard app)

```ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server-public-key>
Endpoint = your-server-ip:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

## Deployment on Digital Ocean

1. Create a new droplet (Ubuntu 22.04 recommended)
2. Copy the setup script to the server:
   ```bash
   scp deploy/setup-digitalocean.sh root@your-droplet:/tmp/
   ```
3. Run the setup:
   ```bash
   ssh root@your-droplet
   chmod +x /tmp/setup-digitalocean.sh
   /tmp/setup-digitalocean.sh
   ```

## Architecture

```
vpn_server/
├── include/vpn/
│   ├── crypto/          # Cryptographic primitives
│   │   ├── curve25519.hpp    # ECDH key exchange
│   │   ├── chacha20poly1305.hpp  # AEAD encryption
│   │   ├── blake2s.hpp       # Hashing/KDF
│   │   └── noise.hpp         # Noise protocol
│   ├── net/             # Networking
│   │   ├── udp_socket.hpp    # UDP I/O
│   │   ├── tun_device.hpp    # TUN interface
│   │   └── address.hpp       # IP addressing
│   ├── protocol/        # WireGuard protocol
│   │   ├── message.hpp       # Message types
│   │   ├── peer.hpp          # Peer state
│   │   ├── session.hpp       # Crypto sessions
│   │   └── timer.hpp         # Protocol timers
│   ├── core/            # Server core
│   │   ├── server.hpp        # Main server
│   │   ├── thread_pool.hpp   # Worker threads
│   │   └── config.hpp        # Configuration
│   └── util/            # Utilities
│       ├── base64.hpp        # Key encoding
│       └── logger.hpp        # Logging
└── src/                 # Implementations
```

## Protocol Details

The server implements the WireGuard protocol as specified in the [whitepaper](https://www.wireguard.com/papers/wireguard.pdf):

- **Noise_IKpsk2** handshake pattern
- **Curve25519** for key exchange
- **ChaCha20-Poly1305** for authenticated encryption
- **BLAKE2s** for hashing and key derivation
- Automatic key rotation every 2 minutes
- Built-in DoS protection with cookies

## License

MIT
