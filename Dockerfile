# Multi-stage build for WireGuard-compatible VPN server with mesh networking
# Stage 1: Build
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    git \
    libsodium-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
WORKDIR /build
COPY CMakeLists.txt .
COPY include/ include/
COPY src/ src/
COPY tools/ tools/
COPY tests/ tests/

# Build in Release mode
RUN mkdir -p build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc) vpn_server vpn_beacon wg-keygen

# Stage 2: Runtime
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libsodium23 \
    iproute2 \
    iptables \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /build/build/vpn_server /usr/local/bin/
COPY --from=builder /build/build/vpn_beacon /usr/local/bin/
COPY --from=builder /build/build/wg-keygen /usr/local/bin/

# Copy default configurations
COPY deploy/sample-server.conf /etc/wireguard/server.conf.example
COPY deploy/sample-mesh.conf /etc/wireguard/mesh.conf.example
COPY deploy/sample-beacon.conf /etc/wireguard/beacon.conf.example

# Create config directory
RUN mkdir -p /etc/wireguard

# Environment variables
ENV VPN_CONFIG=/etc/wireguard/server.conf
ENV VPN_INTERFACE=wg0
ENV VPN_PUBLIC_IP=0.0.0.0

# Expose WireGuard UDP port and Beacon port
EXPOSE 51820/udp
EXPOSE 51821/udp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -x "vpn_server\|vpn_beacon" || exit 1

# Entrypoint script
COPY deploy/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["vpn_server", "--config", "/etc/wireguard/server.conf"]
