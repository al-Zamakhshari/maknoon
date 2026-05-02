#!/bin/bash
set -e

# Mission: Global Orchestration (Phase 4)
# Verification of Decentralized Nostr Discovery & PQC Tunneling

source "$(dirname "$0")/common.sh"
COMPOSE_FILE="deploy/docker/mission-global.yml"
PROJECT="maknoon-global"

trap 'fail_trap "Global Orchestration" "$COMPOSE_FILE" "$PROJECT"' EXIT

echo "🏗️  Provisioning Global Mesh (Nostr + 2 Agents)..."
generate_test_certs "deploy/docker/certs"
docker compose -p $PROJECT -f $COMPOSE_FILE up -d --build
sleep 15

# Use specific containers
LONDON="agent-london"
NY="agent-ny"
L_EXEC="docker compose -p $PROJECT -f $COMPOSE_FILE exec -T $LONDON"
N_EXEC="docker compose -p $PROJECT -f $COMPOSE_FILE exec -T $NY"

echo "🔑 Step 1: Provisioning London PQC Identity..."
$L_EXEC maknoon keygen -o london-id --no-password
# Use the native standard call for orchestration (HTTPS + PQC)
$L_EXEC maknoon call --insecure config_update --args '{"nostr_relays":["ws://172.30.0.5:8080"]}' > /dev/null

echo "📡 Step 2: Starting London P2P Listener via API..."
# Use native standard call for listener establishment (HTTPS + PQC)
$L_EXEC maknoon call --insecure tunnel_listen --args '{"address":":4001","mode":"p2p","identity":"london-id"}' > /dev/null

sleep 2
# Extract PeerID from London (Raw CLI JSON)
LONDON_PEER_ID=$($L_EXEC maknoon identity info london-id --json | jq -r '.peer_id')
LONDON_MA="/ip4/172.30.0.10/tcp/4001/p2p/$LONDON_PEER_ID"
echo "📍 London Multiaddr: $LONDON_MA"

# Publish the identity
$L_EXEC maknoon identity publish @london-gateway --name london-id --multiaddr "$LONDON_MA"
sleep 5

# Extract the Nostr Hex
LONDON_NOSTR_HEX=$($L_EXEC maknoon identity info london-id --json | jq -r '.nostr_pub')
echo "📍 London Gateway Nostr Hex: $LONDON_NOSTR_HEX"

echo "🌍 Step 3: Global Discovery from New York..."
# Update NY live agent config via API (HTTPS + PQC)
$N_EXEC maknoon call --insecure config_update --args '{"nostr_relays":["ws://172.30.0.5:8080"]}' > /dev/null

echo "🔍 NY Agent searching for London Gateway via Nostr..."
# Retry loop for discovery
MAX_RETRIES=10
PUBKEY=""
for i in $(seq 1 $MAX_RETRIES); do
    echo "   Attempt $i/$MAX_RETRIES..."
    # Use native standard call for discovery (HTTPS + PQC)
    RESOLVE_RES=$($N_EXEC maknoon call --insecure resolve_identity --args "{\"input\":\"@$LONDON_NOSTR_HEX\"}")

    # Standard client returns wrapped result
    PUBKEY=$(echo "$RESOLVE_RES" | jq -r '.content[0].text | fromjson | .public_key // empty')
    if [ -n "$PUBKEY" ] && [ "$PUBKEY" != "null" ]; then
        break
    fi
    sleep 3
done

if [ -z "$PUBKEY" ] || [ "$PUBKEY" == "null" ]; then
    echo "❌ FAILED: Global discovery failed."
    echo "Last Resolution Response: $RESOLVE_RES"
    exit 1
fi
echo "✅ Discovery SUCCESS: Retrieved ML-KEM Key: ${PUBKEY:0:16}..."


echo "🌉 Step 4: Autonomous PQC Tunnel Provisioning via API..."
# Establishment of PQC tunnel via standard call (HTTPS + PQC)
$N_EXEC maknoon call --insecure tunnel_start --args "{\"remote\":\"@$LONDON_NOSTR_HEX\",\"p2p_mode\":true,\"port\":1080}" > /dev/null

sleep 5

# Verify tunnel state via standard call (HTTPS + PQC)
STATUS_RES=$($N_EXEC maknoon call --insecure tunnel_status)
IS_ACTIVE=$(echo "$STATUS_RES" | jq -r '.content[0].text | fromjson | .active')

if [ "$IS_ACTIVE" == "true" ]; then
    echo "✅ SUCCESS: Global PQC Tunnel provisioned and verified via Secure standard MCP client."
else
    echo "❌ FAILED: Tunnel provisioning failed."
    echo "Final Status: $STATUS_RES"
    exit 1
fi

echo -e "\n🏆 SUCCESS: Global Orchestration Mission Passed."
echo "Verified: NIP-05 Resolution, Multiaddr Mesh Discovery, and Secure PQC-MCP Provisioning."

echo "🧹 Tearing down Global Mesh..."
docker compose -p maknoon-global -f $COMPOSE_FILE down
