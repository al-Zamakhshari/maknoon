#!/bin/bash
set -e

echo "🕸️ Setting up Maknoon Mesh Network..."

MESH_DIR=$(mktemp -d)
echo "Mesh Directory: $MESH_DIR"

source scripts/common.sh

for i in 1 2 3; do
    NODE_DIR="$MESH_DIR/node$i"
    mkdir -p "$NODE_DIR/keys" "$NODE_DIR/vaults" "$NODE_DIR/certs"
    
    # Generate certs for SSE
    generate_test_certs "$NODE_DIR/certs" > /dev/null 2>&1
    
    # Start MCP Server
    PORT=$((8100 + i))
    export HOME="$NODE_DIR"
    export MAKNOON_PASSPHRASE="mesh-pass-$i"
    
    ./maknoon mcp --transport sse --address ":$PORT" --tls-cert "$NODE_DIR/certs/server.crt" --tls-key "$NODE_DIR/certs/server.key" > "$NODE_DIR/mcp.log" 2>&1 &
    PID=$!
    echo "$PID" > "$NODE_DIR/mcp.pid"
    echo "✅ Node $i started on port $PORT (PID: $PID)"
done

sleep 3
echo "Mesh is ready. Environment path: $MESH_DIR"
echo "$MESH_DIR" > .mesh_env
