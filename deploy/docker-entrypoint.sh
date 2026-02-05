#!/bin/bash
set -e

# WireGuard VPN Server Docker Entrypoint
# Handles TUN device creation and network setup

echo "=== WireGuard VPN Server Entrypoint ==="
echo "Public IP: ${VPN_PUBLIC_IP:-not set}"
echo "Config: ${VPN_CONFIG}"
echo "Interface: ${VPN_INTERFACE}"

# Check if TUN device exists
if [ ! -c /dev/net/tun ]; then
    echo "Creating TUN device..."
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 600 /dev/net/tun
fi

# Generate server keys if they don't exist
KEY_FILE="/etc/wireguard/server_private.key"
if [ ! -f "$KEY_FILE" ]; then
    echo "Generating server keys..."
    wg-keygen genkey > "$KEY_FILE"
    chmod 600 "$KEY_FILE"
    wg-keygen pubkey < "$KEY_FILE" > /etc/wireguard/server_public.key
    echo "Server public key: $(cat /etc/wireguard/server_public.key)"
fi

# Check if config exists, if not create from example
if [ ! -f "${VPN_CONFIG}" ]; then
    if [ -f "/etc/wireguard/server.conf.example" ]; then
        echo "Config not found, creating from example..."
        cp /etc/wireguard/server.conf.example "${VPN_CONFIG}"

        # Replace placeholder with generated key
        PRIVATE_KEY=$(cat "$KEY_FILE")
        sed -i "s|<server-private-key>|${PRIVATE_KEY}|g" "${VPN_CONFIG}"

        echo "Please edit ${VPN_CONFIG} to add your peers"
    else
        echo "ERROR: No config file found at ${VPN_CONFIG}"
        exit 1
    fi
fi

# Enable IP forwarding
echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true

# Set up NAT/masquerading for internet access through VPN
if [ -n "${VPN_SUBNET_V4}" ]; then
    echo "Setting up NAT for ${VPN_SUBNET_V4}..."
    iptables -t nat -A POSTROUTING -s "${VPN_SUBNET_V4}" -o eth0 -j MASQUERADE
    iptables -A FORWARD -i "${VPN_INTERFACE}" -j ACCEPT
    iptables -A FORWARD -o "${VPN_INTERFACE}" -j ACCEPT
fi

if [ -n "${VPN_SUBNET_V6}" ]; then
    echo "Setting up NAT for ${VPN_SUBNET_V6}..."
    ip6tables -t nat -A POSTROUTING -s "${VPN_SUBNET_V6}" -o eth0 -j MASQUERADE 2>/dev/null || true
    ip6tables -A FORWARD -i "${VPN_INTERFACE}" -j ACCEPT 2>/dev/null || true
    ip6tables -A FORWARD -o "${VPN_INTERFACE}" -j ACCEPT 2>/dev/null || true
fi

echo "Starting VPN server..."
exec "$@"
