#!/bin/bash
set -e

echo "🧪 Starting Full Data-Transfer Mesh Orchestration..."

MESH_DIR=$(mktemp -d)
echo "Mesh Directory: $MESH_DIR"
source scripts/common.sh

# 1. Setup 3 nodes
for i in 1 2 3; do
    NODE_DIR="$MESH_DIR/node$i"
    mkdir -p "$NODE_DIR/keys" "$NODE_DIR/vaults" "$NODE_DIR/certs"
    
    # Generate certs for SSE
    generate_test_certs "$NODE_DIR/certs" > /dev/null 2>&1
    
    # Start MCP Server
    PORT=$((8200 + i))
    export HOME="$NODE_DIR"
    export MAKNOON_PASSPHRASE="mesh-pass-$i"
    
    TRACE_FLAG=""
    if [[ "$*" == *"--trace"* ]]; then
        TRACE_FLAG="--trace"
    fi
    
    ./maknoon mcp $TRACE_FLAG --transport sse --address ":$PORT" --tls-cert "$NODE_DIR/certs/server.crt" --tls-key "$NODE_DIR/certs/server.key" > "$NODE_DIR/mcp.log" 2>&1 &
    PID=$!
    echo "$PID" > "$NODE_DIR/mcp.pid"
    echo "✅ Node $i (Port $PORT) started"
done
sleep 3

P1=8201
P2=8202
P3=8203

# 2. Node 1 Listens
echo "📡 Instructing Node 1 to listen..."
LISTEN_RES=$(./maknoon call tunnel_listen --addr "localhost:$P1" --args '{"address": ":0", "mode": "p2p"}' --insecure)
CANONICAL_MA=$(echo "$LISTEN_RES" | jq -r '.content[0].text' | jq -r '.canonical_multiaddr')
NODE1_PEER=$(echo "$LISTEN_RES" | jq -r '.content[0].text' | jq -r '.peer_id')

if [ -z "$CANONICAL_MA" ] || [ "$CANONICAL_MA" == "null" ]; then
    echo "❌ Failed to extract Canonical Multiaddr from Node 1"
    echo "$LISTEN_RES"
    pkill -f "maknoon mcp"
    exit 1
fi
echo "📍 Node 1 is listening at: $CANONICAL_MA"

# 3. Node 2 Connects
echo "🔗 Instructing Node 2 to establish resilient tunnel..."
START2_RES=$(./maknoon call tunnel_start --addr "localhost:$P2" --args "{\"remote\":\"$CANONICAL_MA\",\"p2p_mode\":true,\"data_lanes\":3,\"parity_lanes\":2}" --insecure)
if echo "$START2_RES" | grep -q "isError"; then
    echo "❌ Node 2 Tunnel Failed"
    echo "$START2_RES"
    pkill -f "maknoon mcp"
    exit 1
fi
N2_PORT=$(echo "$START2_RES" | jq -r '.content[0].text' | jq -r '.local_address' | cut -d':' -f2)
echo "✅ Node 2 connected (SOCKS5 bound to port $N2_PORT)"

# 4. Node 3 Connects
echo "🔗 Instructing Node 3 to establish resilient tunnel..."
START3_RES=$(./maknoon call tunnel_start --addr "localhost:$P3" --args "{\"remote\":\"$CANONICAL_MA\",\"p2p_mode\":true,\"data_lanes\":2,\"parity_lanes\":1}" --insecure)
if echo "$START3_RES" | grep -q "isError"; then
    echo "❌ Node 3 Tunnel Failed"
    echo "$START3_RES"
    pkill -f "maknoon mcp"
    exit 1
fi
N3_PORT=$(echo "$START3_RES" | jq -r '.content[0].text' | jq -r '.local_address' | cut -d':' -f2)
echo "✅ Node 3 connected (SOCKS5 bound to port $N3_PORT)"

# 5. Generate Identities for Data Transfer
echo "🔐 Generating cryptographic identities for data transfer..."
./maknoon call identity_keygen --addr "localhost:$P1" --args '{"output":"default"}' --insecure > /dev/null
./maknoon call identity_keygen --addr "localhost:$P2" --args '{"output":"default"}' --insecure > /dev/null
sleep 1

# Fetch Node 1 Public Key for Node 2
INFO_RES=$(./maknoon call identity_info --addr "localhost:$P1" --args '{"name":"default"}' --insecure)
NODE1_PUB=$(echo "$INFO_RES" | jq -r '.content[0].text' | jq -r '.kem_pub')

if [ -z "$NODE1_PUB" ] || [ "$NODE1_PUB" == "null" ]; then
    echo "❌ Failed to extract Public Key from Node 1"
    echo "$INFO_RES"
    pkill -f "maknoon mcp"
    exit 1
fi

# 6. Data Transfer (Node 2 -> Node 1)
echo "📦 Initiating P2P File Transfer (Node 2 -> Node 1)..."
SECRET_TEXT="Agentic Orchestration is Successful"

# Node 1 prepares to receive
echo "📡 Node 1 preparing to receive..."
# No need to pass passphrase anymore because we will use asymmetric encryption
RECEIVE_RES=$(./maknoon call p2p_receive --addr "localhost:$P1" --args "{\"peer_id\":\"\",\"output\":\"$MESH_DIR/node1\"}" --insecure)
if echo "$RECEIVE_RES" | grep -q "isError"; then
    echo "❌ Node 1 Receive Failed"
    echo "$RECEIVE_RES"
    pkill -f "maknoon mcp"
    exit 1
fi

RECEIVE_MA=$(echo "$RECEIVE_RES" | jq -r '.content[0].text' | jq -r '.addrs[] | select(contains("127.0.0.1") and contains("tcp"))' | head -n 1)

if [ -z "$RECEIVE_MA" ] || [ "$RECEIVE_MA" == "null" ]; then
    echo "❌ Failed to extract Receive Multiaddr from Node 1"
    echo "$RECEIVE_RES"
    pkill -f "maknoon mcp"
    exit 1
fi
echo "📍 Node 1 is listening for transfer at: $RECEIVE_MA"

# Node 2 sends data with explicit Public Key
SEND_RES=$(./maknoon call p2p_send --addr "localhost:$P2" --args "{\"text\":\"$SECRET_TEXT\", \"to\":\"$RECEIVE_MA\", \"public_key\":\"$NODE1_PUB\"}" --insecure)
if echo "$SEND_RES" | grep -q "isError"; then
    echo "❌ Node 2 Send Failed"
    echo "$SEND_RES"
    pkill -f "maknoon mcp"
    exit 1
fi

sleep 4

# Check file on Node 1
if grep -q "$SECRET_TEXT" "$MESH_DIR/node1/text-message"; then
    echo "✅ Data transfer verified! Node 1 successfully received the payload."
else
    echo "❌ Data transfer failed. File not found or content mismatch."
    pkill -f "maknoon mcp"
    exit 1
fi

echo "🧹 Cleaning up mesh..."
pkill -f "maknoon mcp"
wait 2>/dev/null || true
rm -rf "$MESH_DIR"
echo "🏆 Mesh Orchestration & Data Transfer Test PASSED"
