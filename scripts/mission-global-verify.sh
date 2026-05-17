#!/bin/bash
set -euo pipefail

# Mission: Global Orchestration (Phase 4)
# Verification of Decentralized Nostr Discovery & PQC Tunneling

source "$(dirname "$0")/common.sh"
COMPOSE_FILE="deploy/docker/mission-global.yml"
PROJECT="maknoon-global"
MISSION_REPORT_FILE="${MISSION_REPORT_FILE:-./mission-reports/mission-global-verify.jsonl}"
mkdir -p "$(dirname "$MISSION_REPORT_FILE")"

trap 'fail_trap "Global Orchestration" "$COMPOSE_FILE" "$PROJECT"' EXIT

echo "🏗️  Provisioning Global Mesh (Nostr + 2 Agents)..."
generate_test_certs "deploy/docker/certs"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --build

L_EXEC="docker compose -p $PROJECT -f $COMPOSE_FILE exec -T agent-london"
N_EXEC="docker compose -p $PROJECT -f $COMPOSE_FILE exec -T agent-ny"

# Wait for MCP SSE server on London to be ready
wait_for_condition "London MCP server ready" 60 \
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T agent-london \
        sh -c "curl -sk -o /dev/null -w '%{http_code}' https://localhost:8080/sse | grep -q 200"

echo "🔑 Step 1: Provisioning London PQC Identity..."
$L_EXEC maknoon keygen -o london-id --no-password
$L_EXEC maknoon call --insecure config_update --args '{"nostr_relays":["ws://172.30.0.5:8080"]}' > /dev/null

echo "📡 Step 2: Starting London P2P Listener via API..."
$L_EXEC maknoon call --insecure tunnel_listen \
    --args '{"address":":4001","mode":"p2p","identity":"london-id"}' > /dev/null

# Wait for tunnel to be listening
wait_for_condition "London P2P port 4001 open" 30 \
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T agent-london \
        sh -c "netstat -tln 2>/dev/null | grep ':4001 ' || ss -tln | grep ':4001 '"

LONDON_PEER_JSON=$($L_EXEC maknoon identity info london-id --json)
LONDON_PEER_ID=$(printf '%s' "$LONDON_PEER_JSON" | jq -r '.peer_id')
[ -z "$LONDON_PEER_ID" ] || [ "$LONDON_PEER_ID" = "null" ] && \
    { echo "❌ Empty peer_id for london"; exit 1; }
LONDON_MA="/ip4/172.30.0.10/tcp/4001/p2p/$LONDON_PEER_ID"
echo "📍 London Multiaddr: $LONDON_MA"

$L_EXEC maknoon identity publish @london-gateway --name london-id --nostr --multiaddr "$LONDON_MA"

LONDON_INFO_JSON=$($L_EXEC maknoon identity info london-id --json)
LONDON_NOSTR_HEX=$(printf '%s' "$LONDON_INFO_JSON" | jq -r '.nostr_pub')
[ -z "$LONDON_NOSTR_HEX" ] || [ "$LONDON_NOSTR_HEX" = "null" ] && \
    { echo "❌ Empty nostr_pub for london"; exit 1; }
echo "📍 London Gateway Nostr Hex: $LONDON_NOSTR_HEX"

echo "🌍 Step 3: Global Discovery from New York..."
$N_EXEC maknoon call --insecure config_update \
    --args '{"nostr_relays":["ws://172.30.0.5:8080"]}' > /dev/null

echo "🔍 NY Agent searching for London Gateway via Nostr..."
PUBKEY=""
for i in $(seq 1 10); do
    echo "   Attempt $i/10..."
    RESOLVE_RES=$($N_EXEC maknoon call --insecure resolve_identity \
        --args "{\"input\":\"@$LONDON_NOSTR_HEX\"}")
    PUBKEY=$(printf '%s' "$RESOLVE_RES" | jq -r '.content[0].text | fromjson | .public_key // empty' 2>/dev/null || true)
    if [ -n "$PUBKEY" ] && [ "$PUBKEY" != "null" ]; then
        break
    fi
    sleep 3  # retry backoff — not a startup wait
done

if [ -z "$PUBKEY" ] || [ "$PUBKEY" = "null" ]; then
    print_result FAIL "Global discovery failed — could not resolve @$LONDON_NOSTR_HEX"
    echo "Last Resolution Response: $RESOLVE_RES"
    exit 1
fi
echo "✅ Discovery SUCCESS: Retrieved ML-KEM Key: ${PUBKEY:0:16}..."

echo "🌉 Step 4: Autonomous PQC Tunnel Provisioning via API..."
$N_EXEC maknoon call --insecure tunnel_start \
    --args "{\"remote\":\"@$LONDON_NOSTR_HEX\",\"p2p_mode\":true,\"port\":1080}" > /dev/null

wait_for_condition "NY tunnel active" 30 \
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T agent-ny \
        sh -c "maknoon call --insecure tunnel_status | jq -e '.content[0].text | fromjson | .active == true'"

STATUS_RES=$($N_EXEC maknoon call --insecure tunnel_status)
IS_ACTIVE=$(printf '%s' "$STATUS_RES" | jq -r '.content[0].text | fromjson | .active')

if [ "$IS_ACTIVE" = "true" ]; then
    print_result PASS "Global PQC Tunnel provisioned via Nostr discovery and secure MCP"
    echo "✅ SUCCESS: Global Orchestration Mission Passed."
else
    print_result FAIL "Tunnel provisioning failed: active=$IS_ACTIVE"
    echo "Final Status: $STATUS_RES"
    exit 1
fi

echo "🧹 Tearing down Global Mesh..."
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down
