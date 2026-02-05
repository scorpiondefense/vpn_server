#!/bin/bash
# Digital Ocean VPN Server Setup Script
# Run this on a fresh Ubuntu 22.04+ droplet

set -e

echo "=== WireGuard VPN Server Setup ==="

# Update system
echo "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install dependencies
echo "Installing build dependencies..."
apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    pkg-config \
    libsodium-dev \
    git

# Enable IP forwarding
echo "Enabling IP forwarding..."
cat > /etc/sysctl.d/99-wireguard.conf << 'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sysctl -p /etc/sysctl.d/99-wireguard.conf

# Create config directory
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

# Clone and build VPN server (adjust repo path as needed)
echo "Building VPN server..."
cd /opt
if [ -d "vpn_server" ]; then
    cd vpn_server
    git pull
else
    git clone <your-repo-url> vpn_server
    cd vpn_server
fi

mkdir -p build
cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja

# Install binaries
echo "Installing binaries..."
cp vpn_server /usr/local/bin/
cp wg-keygen /usr/local/bin/
chmod +x /usr/local/bin/vpn_server
chmod +x /usr/local/bin/wg-keygen

# Generate server keys if not present
if [ ! -f /etc/wireguard/server.key ]; then
    echo "Generating server keys..."
    wg-keygen genkey > /etc/wireguard/server.key
    chmod 600 /etc/wireguard/server.key
    wg-keygen pubkey < /etc/wireguard/server.key > /etc/wireguard/server.pub
fi

SERVER_PRIVATE_KEY=$(cat /etc/wireguard/server.key)
SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server.pub)

# Create server config if not present
if [ ! -f /etc/wireguard/wg0.conf ]; then
    echo "Creating server configuration..."
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = ${SERVER_PRIVATE_KEY}
ListenPort = 51820
Address = 10.0.0.1/24, fd00:vpn::1/64

# Add peers here:
# [Peer]
# PublicKey = <client-public-key>
# AllowedIPs = 10.0.0.2/32
EOF
    chmod 600 /etc/wireguard/wg0.conf
fi

# Install systemd service
echo "Installing systemd service..."
cp /opt/vpn_server/deploy/wireguard-vpn.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable wireguard-vpn

# Configure firewall (UFW)
echo "Configuring firewall..."
ufw allow 51820/udp
ufw allow 22/tcp
ufw --force enable

# Set up NAT for client internet access
echo "Configuring NAT..."
INTERFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+')
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o ${INTERFACE} -j MASQUERADE
ip6tables -t nat -A POSTROUTING -s fd00:vpn::/64 -o ${INTERFACE} -j MASQUERADE

# Save iptables rules
apt-get install -y iptables-persistent
netfilter-persistent save

# Start service
echo "Starting VPN server..."
systemctl start wireguard-vpn
systemctl status wireguard-vpn

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Server Public Key: ${SERVER_PUBLIC_KEY}"
echo ""
echo "To add a client:"
echo "1. Generate client keys: wg-keygen keypair"
echo "2. Add [Peer] section to /etc/wireguard/wg0.conf"
echo "3. Restart: systemctl restart wireguard-vpn"
echo ""
echo "Configure client with:"
echo "  Endpoint: $(curl -s ifconfig.me):51820"
echo "  Server PublicKey: ${SERVER_PUBLIC_KEY}"
