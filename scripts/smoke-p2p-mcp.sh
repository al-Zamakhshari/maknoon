#!/bin/bash
set -e

# Maknoon high-fidelity P2P E2E Verification (V3 - Stable Sessions)
# Uses the unified binary in a 2-node PQC DMZ.

export MAKNOON_PASSPHRASE=mcp-test-secret
export MAKNOON_JSON=1

cleanup() {
    echo "🧹 Tearing down PQC DMZ..."
    [ -n "$SENDER_CURL_PID" ] && kill $SENDER_CURL_PID 2>/dev/null || true
    [ -n "$RECV_CURL_PID" ] && kill $RECV_CURL_PID 2>/dev/null || true
    docker compose -p maknoon -f deploy/docker/mcp.yml down 2>/dev/null || true
    rm -rf *.tmp *.hash *.bin *.txt
}
trap cleanup EXIT

# Session establishment
get_session() {
    local port=$1
    local log="session_$port.txt"
    rm -f "$log"
    # Use --no-buffer and -s -N to ensure we get output immediately
    curl -s -N "http://127.0.0.1:$port/sse" > "$log" &
    local pid=$!
    
    local msg_path=""
    for i in {1..20}; do
        if [ -f "$log" ]; then
            msg_path=$(grep "data: /message" "$log" | head -n 1 | sed 's/data: //' | tr -d '\r\n')
            [ -n "$msg_path" ] && break
        fi
        if ! ps -p $pid > /dev/null; then
            echo "Error: Curl process $pid died on port $port" >&2
            return 1
        fi
        sleep 1
    done
    
    if [ -z "$msg_path" ]; then
        echo "Error: Failed to get session on port $port" >&2
        kill $pid 2>/dev/null || true
        return 1
    fi
    echo "$pid|$msg_path"
}

mcp_call_node() {
    local port=$1
    local path=$2
    local tool=$3
    local args=$4
    local log="session_$port.txt"
    
    local id=$RANDOM
    
    # Send the request
    local status=$(curl -s -w "%{http_code}" -X POST "http://127.0.0.1:$port$path" \
      -H "Content-Type: application/json" \
      -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"tools/call\",
        \"params\": {
          \"name\": \"$tool\",
          \"arguments\": $args
        },
        \"id\": $id
      }" -o /dev/null)
    
    if [ "$status" -ne 202 ] && [ "$status" -ne 200 ]; then
        echo "Error: POST returned HTTP $status" >&2
        return 1
    fi
    
    # Wait for the response in the SSE log
    local res_content=""
    for i in {1..30}; do
        res_content=$(grep "\"id\":$id" "$log" | head -n 1 | sed 's/data: //' | tr -d '\r\n')
        [ -n "$res_content" ] && break
        sleep 1
    done
    
    if [ -z "$res_content" ]; then
        echo "Error: Timeout waiting for MCP response on port $port" >&2
        return 1
    fi
    
    echo "$res_content"
}

echo "🏗️  Provisioning PQC DMZ..."
docker compose -p maknoon -f deploy/docker/mcp.yml up -d --build
sleep 15

echo "🔑 Provisioning PQC Identities..."
docker compose -p maknoon -f deploy/docker/mcp.yml exec -T sender maknoon keygen -o default --no-password --profile nist
docker compose -p maknoon -f deploy/docker/mcp.yml exec -T receiver maknoon keygen -o default --no-password --profile nist

echo "📡 Establishing MCP sessions..."
S_DATA=$(get_session 8080)
SENDER_CURL_PID=$(echo $S_DATA | cut -d'|' -f1)
S_PATH=$(echo $S_DATA | cut -d'|' -f2)

R_DATA=$(get_session 8081)
RECV_CURL_PID=$(echo $R_DATA | cut -d'|' -f1)
R_PATH=$(echo $R_DATA | cut -d'|' -f2)

# 1. Identity Discovery
echo -e "\n📡 Discovering Receiver Identity..."
R_RES=$(mcp_call_node 8081 "$R_PATH" "chat_start" "{\"target\": \"\"}")
R_ID=$(echo "$R_RES" | sed -n 's/.*"peer_id\\":\\"\([^\\"]*\)\\".*/\1/p' | head -n 1)
if [ -z "$R_ID" ]; then
    R_ID=$(echo "$R_RES" | sed -n 's/.*"peer_id":"\([^"]*\)".*/\1/p' | head -n 1)
fi
R_ADDR=$(echo "$R_RES" | grep -oE "/ip4/172.25.0.11/tcp/[0-9]+/p2p/12D3KooW[a-zA-Z0-9]+" | head -n 1)

echo "🆔 Receiver ID: $R_ID"
if [ -z "$R_ID" ]; then echo "❌ Identity discovery failed."; exit 1; fi

# 2. Chat Handshake
echo -e "\n💬 Scenario: Identity-bound Chat Handshake"
S_RES=$(mcp_call_node 8080 "$S_PATH" "chat_start" "{\"target\": \"\"}")
S_ADDR=$(echo "$S_RES" | grep -oE "/ip4/172.25.0.10/tcp/[0-9]+/p2p/12D3KooW[a-zA-Z0-9]+" | head -n 1)

echo "🤝 Receiver: Joining Sender via direct Multiaddr: $S_ADDR"
JOIN_RES=$(mcp_call_node 8081 "$R_PATH" "chat_start" "{\"target\": \"$S_ADDR\"}")
echo "Join Response: $JOIN_RES"

if echo "$JOIN_RES" | grep -q "\"status\":[[:space:]]*\"established\"" || echo "$JOIN_RES" | grep -q "\\\"status\\\":\\\"established\\\""; then
    echo "✅ SUCCESS: P2P Chat handshake verified."
else
    echo "❌ FAILURE: Chat handshake failed."
    exit 1
fi

echo -e "\n🏆 P2P MCP CORE VERIFIED."
