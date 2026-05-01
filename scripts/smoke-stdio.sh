#!/bin/bash
set -e

# Maknoon L4 - MCP Stdio Mission Lifecycle Test
# Verifies that the tunnel remains active after tool call.

export MAKNOON_HOME=$(mktemp -d)
export MAKNOON_PASSPHRASE=smoke-test-secret

cleanup() {
    echo "🧹 Cleaning up..."
    docker compose -p maknoon -f deploy/docker/test.yml down
    rm -rf "$MAKNOON_HOME"
    rm -f call.json resp.json stdio_tunnel.log mcp_pipe
}

trap cleanup EXIT

echo "🏗️  Starting PQC DMZ Environment..."
docker compose -p maknoon -f deploy/docker/test.yml up -d --build
sleep 8

echo "🌐 Resolving P2P Multiaddr..."
PEER_ID=$(docker compose -p maknoon -f deploy/docker/test.yml logs gateway-p2p | grep "Peer ID:" | head -n 1 | awk '{print $NF}' | tr -d '\r\n')
P2P_ADDR="/ip4/127.0.0.1/tcp/4435/p2p/$PEER_ID"

echo "🔐 Seeding Vault..."
echo "pqc-secret-123" | ./maknoon vault set "gateway-mission-1" --user "admin" --overwrite --json > /dev/null

echo "📡 Verification 1: Tool Discovery"
echo '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}' | ./maknoon mcp --transport stdio > resp.json 2>/dev/null || true
grep -q "tunnel_start" resp.json && echo "✅ tools/list passed."

echo "📡 Verification 2: Provisioning L4 Tunnel"
mkfifo mcp_pipe
# Keep the process alive by keeping the input pipe open
(
  echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"tunnel_start","arguments":{"p2p_mode":true,"p2p_addr":"'$P2P_ADDR'","port":1085}},"id":3}'
  tail -f /dev/null
) > mcp_pipe &

./maknoon mcp --transport stdio < mcp_pipe > stdio_tunnel.log 2>&1 &
MCP_PID=$!

echo "⏳ Waiting 10s for P2P Handshake and SOCKS5 startup..."
sleep 10
if nc -z 127.0.0.1 1085; then
    echo "✅ SUCCESS: SOCKS5 is live on 1085."
else
    echo "❌ FAILURE: SOCKS5 gateway failed to bind."
    echo "--- LOGS ---"
    cat stdio_tunnel.log
    echo "------------"
    exit 1
fi

echo -e "\n🏆 MCP STDIO SMOKE TEST PASSED."
