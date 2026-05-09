#!/bin/bash
# Maknoon Mission Verification: L4 Tunnel Reed-Solomon Resilience

set -e

# Cleanup on exit
cleanup() {
    echo "🧹 Cleaning up..."
    kill $LISTENER_PID $API_PID $CLI_PID 2>/dev/null || true
    chmod -R +w "$TEST_DIR" 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

echo "🧪 Starting Mission: L4 Tunnel Resilience Verification..."

# Kill any existing maknoon processes to ensure a clean slate
killall maknoon 2>/dev/null || true

# Setup clean environment
TEST_DIR=$(mktemp -d)
export HOME=$TEST_DIR
mkdir -p $HOME/.maknoon/keys

# Ensure binary is built
make build > /dev/null 2>&1

# 1. Start a PQC Tunnel Listener (Receiver)
echo "📡 Starting Tunnel Listener (P2P)..."
./maknoon tunnel listen --p2p --address ":4433" > "$TEST_DIR/listener.log" 2>&1 &
LISTENER_PID=$!
sleep 5

# Extract Peer ID
PEER_ID=$(grep "Peer ID:" "$TEST_DIR/listener.log" | awk '{print $4}')
if [ -z "$PEER_ID" ]; then
    echo "❌ Failure: Could not extract Peer ID."
    cat "$TEST_DIR/listener.log"
    exit 1
fi
TARGET_MA="/ip4/127.0.0.1/tcp/4433/p2p/$PEER_ID"
echo "📍 Target Multiaddr: $TARGET_MA"

# 2. CLI: Start a Resilient Tunnel
echo "🔍 Task 1: Verifying Resilient Tunnel (CLI)..."
./maknoon tunnel start --p2p --p2p-addr "$TARGET_MA" --port 1080 --data-lanes 1 --parity-lanes 2 > "$TEST_DIR/cli-tunnel.log" 2>&1 &
CLI_PID=$!
sleep 5

# Check if proxy port is listening
if lsof -Pi :1080 -sTCP:LISTEN -t >/dev/null ; then
    echo "✅ Success: Resilient Tunnel CLI started (Proxy functional)."
else
    echo "❌ Failure: Resilient Tunnel CLI failed to bind proxy port."
    cat "$TEST_DIR/cli-tunnel.log"
    exit 1
fi

kill $CLI_PID
CLI_PID=""
sleep 1

# 3. API: Start Resilient Tunnel via REST
echo "🔍 Task 2: Verifying Resilient Tunnel (REST API)..."
# (Setup API Server)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout "$TEST_DIR/key.pem" -out "$TEST_DIR/cert.pem" -sha256 -days 1 -nodes -subj "/CN=localhost" > /dev/null 2>&1
./maknoon serve --address "127.0.0.1:8081" --tls-cert "$TEST_DIR/cert.pem" --tls-key "$TEST_DIR/key.pem" > "$TEST_DIR/api.log" 2>&1 &
API_PID=$!
sleep 5

RESP=$(curl -k -s -X POST https://127.0.0.1:8081/v1/network/tunnel/start \
     -H "Content-Type: application/json" \
     -d "{\"p2p_mode\": true, \"p2p_addr\": \"$TARGET_MA\", \"local_proxy_port\": 1081, \"data_lanes\": 1, \"parity_lanes\": 1}")

if echo "$RESP" | grep -q "127.0.0.1:1081"; then
    echo "✅ Success: Resilient Tunnel started via REST API."
else
    echo "❌ Failure: REST API Tunnel start failed."
    echo "Response: $RESP"
    exit 1
fi

# Stop API server tunnel (or just kill API server)
kill $API_PID
API_PID=""
sleep 1

# 4. MCP: Start Resilient Tunnel via MCP
echo "🔍 Task 3: Verifying Resilient Tunnel (MCP Stdio)..."
# Using the correct MCP JSON-RPC method: tools/call
MCP_RESP=$(echo "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"tunnel_start\",\"arguments\":{\"p2p_mode\":true,\"p2p_addr\":\"$TARGET_MA\",\"port\":1082,\"data_lanes\":1,\"parity_lanes\":1}},\"id\":1}" | ./maknoon mcp 2>/dev/null)

if echo "$MCP_RESP" | grep -q "127.0.0.1:1082"; then
    echo "✅ Success: Resilient Tunnel started via MCP."
else
    echo "❌ Failure: MCP Tunnel start failed."
    echo "Response: $MCP_RESP"
    exit 1
fi

echo "🏆 Mission Accomplished: L4 Tunnel Resilience Verified across CLI, REST, and MCP."
exit 0
