#!/bin/bash
set -e

# Maknoon Industrial Smoke Suite: Agent Hardening & Resilient Metrics
# Verifies Workspace Isolation, Encrypted Agent Memory, and Tunnel Resilience.

echo "🧪 Starting Mission: Agent Hardening & Resilience (Pure Binary + MCP E2E)..."

source scripts/common.sh

# Setup clean environment
TEST_DIR=$(mktemp -d)
export HOME=$TEST_DIR
mkdir -p $HOME/.maknoon/keys
mkdir -p $HOME/.maknoon/vaults

export MAKNOON_PASSPHRASE="agent-smoke-pass"
export MAKNOON_AUDIT_ENABLED="true"
export MAKNOON_AUDIT_LOG_FILE="${TEST_DIR}/agent_audit.log"

# --- PHASE 1: CLI End-to-End ---

echo "🔍 Task 1: Verifying Workspace CLI..."
WORKSPACE_PATH=$(./maknoon workspace create --name "smoke-cli" --json | jq -r '.path')
if [ ! -d "$WORKSPACE_PATH" ]; then
    echo "❌ Failure: Workspace directory not created."
    exit 1
fi
echo "✅ Workspace created at $WORKSPACE_PATH"

./maknoon workspace shred "$WORKSPACE_PATH" --json > /dev/null
if [ -d "$WORKSPACE_PATH" ]; then
    echo "❌ Failure: Workspace directory still exists after shred."
    exit 1
fi
echo "✅ Workspace shredded successfully."

echo "🔍 Task 2: Verifying Vault Blob CLI..."
./maknoon vault set-blob "agent-memory-key" --data "secret-agent-context" --vault "memory" --overwrite --json > /dev/null
BLOB_DATA=$(./maknoon vault get-blob "agent-memory-key" --vault "memory")
if [ "$BLOB_DATA" != "secret-agent-context" ]; then
    echo "❌ Failure: Blob data mismatch. Got: $BLOB_DATA"
    exit 1
fi
echo "✅ Vault Blob stored and retrieved correctly."

# --- PHASE 2: MCP Server E2E ---

echo "🔐 Generating test certificates for MCP SSE..."
generate_test_certs "${TEST_DIR}/certs"
CERT="${TEST_DIR}/certs/server.crt"
KEY="${TEST_DIR}/certs/server.key"

echo "🚀 Task 3: Starting Maknoon MCP Server (Daemon)..."
# Find a free port
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')
./maknoon mcp --transport sse --address ":$PORT" --tls-cert "$CERT" --tls-key "$KEY" > "${TEST_DIR}/mcp_server.log" 2>&1 &
MCP_PID=$!
sleep 5

echo "🔍 Task 4: Verifying MCP Workspace Tool via 'maknoon call'..."
# Create workspace via MCP
set +e
MCP_RES=$(./maknoon call workspace_create --addr "localhost:$PORT" --args '{"name":"mcp-smoke"}' --insecure 2>&1)
CALL_EXIT=$?
set -e

if [ $CALL_EXIT -ne 0 ]; then
    echo "❌ Failure: 'maknoon call' exited with $CALL_EXIT"
    echo "Response: $MCP_RES"
    echo "--- Server Logs ---"
    cat "${TEST_DIR}/mcp_server.log"
    kill $MCP_PID
    exit 1
fi

MCP_PATH=$(echo "$MCP_RES" | jq -r '.content[0].text' | jq -r '.path')
echo "✅ MCP Workspace created at $MCP_PATH"

# Shred workspace via MCP
./maknoon call workspace_shred --addr "localhost:$PORT" --args "{\"path\":\"$MCP_PATH\"}" --insecure > /dev/null
if [ -d "$MCP_PATH" ]; then
    echo "❌ Failure: MCP Workspace shred tool failed."
    kill $MCP_PID
    exit 1
fi
echo "✅ MCP Workspace shredded successfully."

echo "🔍 Task 5: Verifying Resilient Tunnel Metrics via MCP 'network_status'..."
# 1. Start a listener
./maknoon tunnel listen --p2p --address ":0" > "${TEST_DIR}/p2p_listener.log" 2>&1 &
LP2P_PID=$!
sleep 5

# Extract full loopback multiaddr from the listener log
REMOTE_MA=$(grep "/ip4/127.0.0.1/tcp/" "${TEST_DIR}/p2p_listener.log" | head -n 1 | sed 's/.*Adrs: \[//' | sed 's/,.*//' | tr -d '[]" -')
# If bracket-style extraction fails, try fallback
if [ -z "$REMOTE_MA" ]; then
    REMOTE_MA=$(grep "/ip4/127.0.0.1/tcp/" "${TEST_DIR}/p2p_listener.log" | grep -o "/ip4/127.0.0.1/tcp/[0-9]*/p2p/[A-Za-z0-9]*" | head -n 1 | tr -d ' -')
fi

if [ -z "$REMOTE_MA" ]; then
    echo "❌ Failure: Could not extract Multiaddr from listener log."
    echo "--- Listener Logs ---"
    cat "${TEST_DIR}/p2p_listener.log"
    kill $MCP_PID $LP2P_PID
    exit 1
fi
echo "📍 Extracted Multiaddr: $REMOTE_MA"

# 2. Establish resilient tunnel VIA MCP
echo "📡 Establishing Resilient Tunnel via MCP..."
START_RES=$(./maknoon call tunnel_start --addr "localhost:$PORT" --args "{\"remote\":\"$REMOTE_MA\",\"p2p_mode\":true,\"data_lanes\":2,\"parity_lanes\":1}" --insecure)
if echo "$START_RES" | grep -q "isError"; then
    echo "❌ Failure: tunnel_start via MCP failed."
    echo "Response: $START_RES"
    kill $MCP_PID $LP2P_PID
    exit 1
fi
sleep 5

# 3. Check metrics via MCP network_status
NET_STATUS=$(./maknoon call network_status --addr "localhost:$PORT" --insecure | jq -r '.content[0].text')
DATA_LANES=$(echo "$NET_STATUS" | jq -r '.tunnel.data_lanes')
HEALTHY_LANES=$(echo "$NET_STATUS" | jq -r '.tunnel.healthy_lanes')

echo "Resilience Stats: Data=$DATA_LANES, Healthy=$HEALTHY_LANES"

if [ "$DATA_LANES" -eq 2 ] && [ "$HEALTHY_LANES" -eq 3 ]; then
    echo "✅ Success: MCP Resilient Tunnel Metrics verified."
else
    echo "❌ Failure: Resilience Metrics mismatch in MCP server."
    echo "Net Status: $NET_STATUS"
    kill $MCP_PID $LP2P_PID
    exit 1
fi

# Cleanup
echo "🧹 Cleaning up processes..."
kill $MCP_PID $LP2P_PID
wait $MCP_PID $LP2P_PID 2>/dev/null || true

echo "📜 Checking Forensic Audit Log for all E2E events..."
if grep -q "workspace_create" "$MAKNOON_AUDIT_LOG_FILE" && \
   grep -q "vault_set" "$MAKNOON_AUDIT_LOG_FILE" && \
   grep -q "tunnel_start" "$MAKNOON_AUDIT_LOG_FILE"; then
    echo "✅ Success: All E2E events forensically audited."
else
    echo "❌ Failure: Forensic audit trail incomplete."
    exit 1
fi

echo "🏆 Mission Accomplished: Agent Hardening & Resilience Verified (100% E2E Coverage)."
chmod -R +w "$TEST_DIR"
rm -rf "$TEST_DIR"
exit 0
