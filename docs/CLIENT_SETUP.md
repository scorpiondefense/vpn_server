# Connecting to the VPN Server — macOS & Linux

This guide covers how to connect to the Scorpion Intelligence WireGuard VPN server from macOS and Linux clients. The server is fully compatible with native WireGuard clients.

## Prerequisites

You will need:
- The **server's public key** (obtain from your server administrator)
- The **server endpoint** (IP address and port, e.g. `129.212.217.164:51820`)
- An **assigned tunnel IP** (e.g. `10.0.0.2/32`)

## 1. Generate Client Keys

### Using wg-keygen (from this repo)

If you have built the VPN server locally:

```bash
cd build
./wg-keygen genkey > client.key
./wg-keygen pubkey < client.key > client.pub
```

### Using WireGuard tools

Alternatively, use the standard `wg` command-line tool:

```bash
wg genkey | tee client.key | wg pubkey > client.pub
```

Your **client public key** (contents of `client.pub`) must be added to the server's configuration as a `[Peer]` entry before you can connect.

## 2. Create Client Configuration

Create a file named `wg0.conf`:

```ini
[Interface]
PrivateKey = <contents-of-client.key>
Address = 10.0.0.2/32, fd00:vpn::2/128
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = <server-public-key>
Endpoint = 129.212.217.164:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

**Configuration fields:**

| Field | Description |
|-------|-------------|
| `PrivateKey` | Your client private key (from `client.key`) |
| `Address` | Your assigned tunnel IP address |
| `DNS` | DNS servers to use while connected |
| `PublicKey` | The server's public key |
| `Endpoint` | Server IP and port |
| `AllowedIPs` | `0.0.0.0/0, ::/0` routes all traffic through the VPN. Use specific subnets (e.g. `10.0.0.0/24`) for split tunneling |
| `PersistentKeepalive` | Sends a keepalive packet every 25 seconds to maintain NAT mappings |

---

## macOS Setup

### Option A: WireGuard GUI App (Recommended)

1. Install WireGuard from the [Mac App Store](https://apps.apple.com/us/app/wireguard/id1451685025) or via Homebrew:

   ```bash
   brew install --cask wireguard-tools
   ```

2. Open the WireGuard app.

3. Click **Import Tunnel(s) from File** and select your `wg0.conf`.

4. Click **Activate** to connect.

5. The menu bar icon will indicate connection status.

### Option B: Command Line with wg-quick

1. Install WireGuard tools:

   ```bash
   brew install wireguard-tools
   ```

2. Copy your config file:

   ```bash
   sudo mkdir -p /etc/wireguard
   sudo cp wg0.conf /etc/wireguard/wg0.conf
   sudo chmod 600 /etc/wireguard/wg0.conf
   ```

3. Connect:

   ```bash
   sudo wg-quick up wg0
   ```

4. Verify the connection:

   ```bash
   sudo wg show
   ```

   You should see output like:

   ```
   interface: wg0
     public key: <your-public-key>
     private key: (hidden)
     listening port: 51820

   peer: <server-public-key>
     endpoint: 129.212.217.164:51820
     allowed ips: 0.0.0.0/0, ::/0
     latest handshake: 5 seconds ago
     transfer: 1.24 KiB received, 1.08 KiB sent
     persistent keepalive: every 25 seconds
   ```

5. Disconnect:

   ```bash
   sudo wg-quick down wg0
   ```

---

## Linux Setup

### Ubuntu / Debian

1. Install WireGuard:

   ```bash
   sudo apt update
   sudo apt install wireguard wireguard-tools
   ```

2. Copy your config file:

   ```bash
   sudo cp wg0.conf /etc/wireguard/wg0.conf
   sudo chmod 600 /etc/wireguard/wg0.conf
   ```

3. Connect:

   ```bash
   sudo wg-quick up wg0
   ```

4. Verify:

   ```bash
   sudo wg show
   ```

5. Disconnect:

   ```bash
   sudo wg-quick down wg0
   ```

### Fedora / RHEL / CentOS

1. Install WireGuard:

   ```bash
   sudo dnf install wireguard-tools
   ```

2. Follow the same steps 2–5 as Ubuntu above.

### Arch Linux

1. Install WireGuard:

   ```bash
   sudo pacman -S wireguard-tools
   ```

2. Follow the same steps 2–5 as Ubuntu above.

### Enable on Boot (systemd)

To automatically connect on startup:

```bash
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
```

Check status:

```bash
sudo systemctl status wg-quick@wg0
```

---

## Verifying Your Connection

Once connected, verify that traffic is flowing through the VPN:

```bash
# Check your public IP (should show the VPN server's IP)
curl -s https://ifconfig.me

# Check WireGuard interface stats
sudo wg show

# Ping the VPN gateway
ping 10.0.0.1

# Check routing table
ip route show  # Linux
netstat -rn     # macOS
```

## Troubleshooting

### No handshake / connection timeout

- Ensure UDP port **51820** is not blocked by your local firewall or network.
- Verify the server endpoint IP and port are correct.
- Confirm your client public key has been added to the server's `[Peer]` configuration.

### Handshake succeeds but no internet

- Check that the server has IP forwarding enabled and NAT/masquerading configured.
- Verify `AllowedIPs = 0.0.0.0/0, ::/0` is set in your client config.
- Try setting a different DNS server (e.g. `8.8.8.8`).

### DNS resolution fails

- Add `DNS = 1.1.1.1` to your `[Interface]` section.
- On Linux, you may need to install `resolvconf`:
  ```bash
  sudo apt install resolvconf
  ```

### MTU issues (slow speeds or dropped packets)

- Add `MTU = 1380` to the `[Interface]` section of your client config.
- This is sometimes needed on networks with smaller MTU (e.g. behind another VPN or PPPoE).

### Permission denied on macOS

- `wg-quick` requires `sudo` on macOS.
- If using the GUI app, it will prompt for permission to create a network tunnel.

## Server-Side: Adding a New Client

On the server, add a `[Peer]` block to `/etc/wireguard/server.conf`:

```ini
[Peer]
PublicKey = <new-client-public-key>
AllowedIPs = 10.0.0.X/32, fd00:vpn::X/128
```

Then restart the VPN server to pick up the change. Each client must have a unique tunnel IP address.
