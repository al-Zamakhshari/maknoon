#!/bin/bash
set -e

# Maknoon Industrial Smoke Test - P2P via MCP SSE
# Targets: p2p_send, p2p_receive via SSE JSON-RPC

export MAKNOON_PASSPHRASE=industrial-mcp-secret
export MAKNOON_JSON=1

TEST_BASE="/tmp/maknoon_mcp_p2p"
mkdir -p "$TEST_BASE/node1" "$TEST_BASE/node2"

cleanup() {
    echo "🧹 Cleaning up..."
    killall mcp-server 2>/dev/null || true
    rm -rf "$TEST_BASE"
    rm -f mcp-server
}

trap cleanup EXIT

echo "🏗️  Building standalone MCP server..."
go build -o mcp-server ./integrations/mcp

echo "🚀 Starting Node 1 (Sender) on port 8080..."
(export HOME="$TEST_BASE/node1" && ./mcp-server --transport sse --port 8080 > "$TEST_BASE/node1.log" 2>&1) &
sleep 3

echo "🚀 Starting Node 2 (Receiver) on port 8081..."
(export HOME="$TEST_BASE/node2" && ./mcp-server --transport sse --port 8081 > "$TEST_BASE/node2.log" 2>&1) &
sleep 3

echo "🔑 Initializing Identities..."
# Command node2 to get its PeerID via chat_start (host mode)
# In industrial testing, we use a simple HTTP tool-call pattern
echo "📡 Querying Node 2 PeerID..."
# We start a chat as a hack to get the PeerID
NODE2_RES=$(curl -s -X POST http://localhost:8081/tools/call -H "Content-Type: application/json" -d '{
  "name": "chat_start",
  "arguments": {"target": ""}
}')
NODE2_ID=$(echo "$NODE2_RES" | grep -oE "12D3KooW[a-zA-Z0-9]+")
echo "🆔 Node 2 PeerID: $NODE2_ID"

if [ -z "$NODE2_ID" ]; then
    echo "❌ Failed to get PeerID from Node 2"
    cat "$TEST_BASE/node2.log"
    exit 1
fi

echo "📦 Preparing forensic asset on Node 1..."
dd if=/dev/urandom of="$TEST_BASE/node1/top_secret.bin" bs=1k count=10 > /dev/null 2>&1
sha256sum "$TEST_BASE/node1/top_secret.bin" | awk '{print $1}' > "$TEST_BASE/original.hash"

echo "📥 Commanding Node 2 to WAIT for P2P transfer..."
(
curl -s -X POST http://localhost:8081/tools/call -H "Content-Type: application/json" -d "{
  \"name\": \"p2p_receive\",
  \"arguments\": {
    \"output\": \"$TEST_BASE/node2/recovered.bin\"
  }
}" > "$TEST_BASE/node2_recv_res.json"
) &
RECV_CURL_PID=$!
sleep 3

echo "🚀 Commanding Node 1 to SEND to Node 2..."
NODE1_SEND_RES=$(curl -s -X POST http://localhost:8080/tools/call -H "Content-Type: application/json" -d "{
  \"name\": \"p2p_send\",
  \"arguments\": {
    \"path\": \"$TEST_BASE/node1/top_secret.bin\",
    \"to\": \"$NODE2_ID\"
  }
}")
echo "📡 Node 1 response: $NODE1_SEND_RES"

echo "⏳ Waiting for transfer to complete..."
wait $RECV_CURL_PID || true

echo "🛡️  Performing forensic audit of recovered data..."
if [ -f "$TEST_BASE/node2/recovered.bin" ]; then
    sha256sum "$TEST_BASE/node2/recovered.bin" | awk '{print $1}' > "$TEST_BASE/recovered.hash"
    if diff -q "$TEST_BASE/original.hash" "$TEST_BASE/recovered.hash" > /dev/null; then
        echo "✅ FORENSIC AUDIT SUCCESS: Byte-perfect integrity over libp2p."
    else
        echo "❌ FORENSIC AUDIT FAILED: Data corruption detected."
        exit 1
    fi
else
    echo "❌ TRANSFER FAILED: Node 2 never received the file."
    echo "--- Node 2 Logs ---"
    cat "$TEST_BASE/node2.log"
    exit 1
fi

echo -e "\n🏆 MCP P2P E2E SUITE PASSED."
