#!/bin/bash
set -euo pipefail

# Generate mesh VPN configuration files for the Docker example
# Creates configs/ directory with beacon + 3 node configurations

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIGS_DIR="${SCRIPT_DIR}/configs"
KEYGEN="${SCRIPT_DIR}/../../build/wg-keygen"

# Check if wg-keygen is built
if [ ! -f "$KEYGEN" ]; then
    echo "Error: wg-keygen not found at $KEYGEN"
    echo "Build the project first: mkdir -p build && cd build && cmake .. && make wg-keygen"
    exit 1
fi

mkdir -p "$CONFIGS_DIR"

echo "Generating mesh VPN configurations..."

# Generate keys for all nodes
BEACON_PRIV=$($KEYGEN keypair 2>/dev/null | head -1)
BEACON_PUB=$($KEYGEN keypair 2>/dev/null | tail -1)

# Re-generate beacon keys (keypair returns priv\npub)
BEACON_KEYS=$($KEYGEN keypair 2>/dev/null)
BEACON_PRIV=$(echo "$BEACON_KEYS" | head -1)
BEACON_PUB=$(echo "$BEACON_KEYS" | tail -1)

NODE_A_KEYS=$($KEYGEN keypair 2>/dev/null)
NODE_A_PRIV=$(echo "$NODE_A_KEYS" | head -1)

NODE_B_KEYS=$($KEYGEN keypair 2>/dev/null)
NODE_B_PRIV=$(echo "$NODE_B_KEYS" | head -1)

NODE_C_KEYS=$($KEYGEN keypair 2>/dev/null)
NODE_C_PRIV=$(echo "$NODE_C_KEYS" | head -1)

# Generate a shared network secret
NETWORK_SECRET=$(openssl rand -base64 32)
NETWORK_NAME="mesh-example"

echo "Beacon public key: $BEACON_PUB"

# Beacon config
cat > "$CONFIGS_DIR/beacon.conf" << EOF
[Interface]
PrivateKey = $BEACON_PRIV
ListenPort = 51821

[Beacon]
NetworkName = $NETWORK_NAME
NetworkSecret = $NETWORK_SECRET
MaxPeers = 100
PeerExpiry = 300
EOF

# Node A config
cat > "$CONFIGS_DIR/node-a.conf" << EOF
[Interface]
PrivateKey = $NODE_A_PRIV
ListenPort = 51820
Address = 10.100.0.1/16

[Mesh]
NetworkName = $NETWORK_NAME
NetworkSecret = $NETWORK_SECRET
BeaconAddress = 172.20.0.10:51821
BeaconPublicKey = $BEACON_PUB
AutoConnect = true
MaxPeers = 100
EOF

# Node B config
cat > "$CONFIGS_DIR/node-b.conf" << EOF
[Interface]
PrivateKey = $NODE_B_PRIV
ListenPort = 51820
Address = 10.100.0.2/16

[Mesh]
NetworkName = $NETWORK_NAME
NetworkSecret = $NETWORK_SECRET
BeaconAddress = 172.20.0.10:51821
BeaconPublicKey = $BEACON_PUB
AutoConnect = true
MaxPeers = 100
EOF

# Node C config
cat > "$CONFIGS_DIR/node-c.conf" << EOF
[Interface]
PrivateKey = $NODE_C_PRIV
ListenPort = 51820
Address = 10.100.0.3/16

[Mesh]
NetworkName = $NETWORK_NAME
NetworkSecret = $NETWORK_SECRET
BeaconAddress = 172.20.0.10:51821
BeaconPublicKey = $BEACON_PUB
AutoConnect = true
MaxPeers = 100
EOF

echo ""
echo "Configuration files generated in $CONFIGS_DIR/"
echo "  beacon.conf  - Beacon server"
echo "  node-a.conf  - Mesh node A (10.100.0.1)"
echo "  node-b.conf  - Mesh node B (10.100.0.2)"
echo "  node-c.conf  - Mesh node C (10.100.0.3)"
echo ""
echo "To start the mesh:"
echo "  docker-compose up --build"
echo ""
echo "To test connectivity:"
echo "  docker exec mesh-example-node-a-1 ping -c 3 10.100.0.2"
echo "  docker exec mesh-example-node-b-1 ping -c 3 10.100.0.3"
echo "  docker exec mesh-example-node-c-1 ping -c 3 10.100.0.1"
