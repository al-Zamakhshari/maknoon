#!/bin/bash
set -euo pipefail

# Mission: Zero-Trust Mesh (Phase 1)
# Verification of Identity-Based Tunneling

source "$(dirname "$0")/common.sh"
COMPOSE_FILE="deploy/docker/mission-mesh.yml"
MISSION_REPORT_FILE="${MISSION_REPORT_FILE:-./mission-reports/mission-mesh-verify.jsonl}"
mkdir -p "$(dirname "$MISSION_REPORT_FILE")"

trap 'fail_trap "Zero-Trust Mesh" "$COMPOSE_FILE"' EXIT

echo "🏗️  Provisioning Zero-Trust Mesh..."
docker compose -f "$COMPOSE_FILE" up -d --build

# Wait for Gateway to log a non-loopback multiaddr
wait_for_condition "gateway multiaddr in logs" 180 \
    docker compose -f "$COMPOSE_FILE" logs maknoon-gateway \| grep -q "/ip4/[^1]"
GATEWAY_ADDR=$(docker compose -f "$COMPOSE_FILE" logs maknoon-gateway \
    | grep "/ip4/" | grep -v "127.0.0.1" | head -n 1 | awk '{print $NF}' | tr -d '\r')

if [ -z "$GATEWAY_ADDR" ]; then
    echo "❌ FAILED: Could not retrieve Gateway Multiaddr."
    docker compose -f "$COMPOSE_FILE" logs maknoon-gateway
    exit 1
fi
echo "🆔 Gateway Multiaddr Found: $GATEWAY_ADDR"

# Start the Client Tunnel
echo "🤝 Establishing Identity-Bound Tunnel from Client..."
CLIENT_CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps -q maknoon-client)

docker exec -d "$CLIENT_CONTAINER" sh -c \
    "maknoon keygen --no-password -o client-id && \
     maknoon tunnel start --p2p --p2p-addr $GATEWAY_ADDR --port 1080 --identity client-id > tunnel.log 2>&1"

wait_for_port "$CLIENT_CONTAINER" 1080 60 || exit 1

# Test Connectivity
echo "🧪 Verifying end-to-end connectivity via SOCKS5..."
TEST_RESULT=$(docker exec "$CLIENT_CONTAINER" \
    curl -v -s --socks5-hostname 127.0.0.1:1080 http://provider:80 2>&1)

if printf '%s' "$TEST_RESULT" | grep -q "Directory listing for /"; then
    print_result PASS "Zero-Trust Mesh verified — traffic routed through PQC tunnel"
    echo "✅ SUCCESS: Zero-Trust Mesh verified!"
else
    print_result FAIL "Unexpected response or connection failure: $TEST_RESULT"
    exit 1
fi

echo "🧹 Tearing down Mesh..."
docker compose -f "$COMPOSE_FILE" down
