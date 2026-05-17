#!/bin/bash
set -euo pipefail

# Mission: Orchestrated Quorum Unlocking (Phase 6.2)
# Verification of Automated P2P-based Vault Access

source "$(dirname "$0")/common.sh"
COMPOSE_FILE="deploy/docker/mission-orchestrated.yml"
MISSION_REPORT_FILE="${MISSION_REPORT_FILE:-./mission-reports/mission-orchestrated-quorum.jsonl}"
mkdir -p "$(dirname "$MISSION_REPORT_FILE")"

setup_mission_logs
trap 'fail_trap "Orchestrated Quorum" "$COMPOSE_FILE"' EXIT

echo "🏗️  Provisioning Orchestrated Quorum Mesh..."
docker compose -f "$COMPOSE_FILE" up -d --build

# Step 1: Generate Identities and Extract Peer IDs
echo "🆔 Generating Identities..."
declare -a GUARDIAN_ADDRS

for j in {1..3}; do
    checked_compose_exec "$COMPOSE_FILE" "guardian-$j" \
        maknoon keygen --no-password -o "g${j}" > /dev/null
    ID_JSON=$(checked_compose_exec "$COMPOSE_FILE" "guardian-$j" \
        maknoon identity info "g${j}" --json)
    ID=$(printf '%s' "$ID_JSON" | jq -r '.peer_id')
    [ -z "$ID" ] || [ "$ID" = "null" ] && { echo "❌ Empty peer_id for guardian-$j"; exit 1; }
    IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "docker-guardian-${j}-1")
    ADDR="/ip4/$IP/tcp/4000/p2p/$ID"
    GUARDIAN_ADDRS+=("$ADDR")
    echo "  - Guardian-$j: $ADDR"
done

checked_compose_exec "$COMPOSE_FILE" initiator \
    maknoon keygen --no-password -o default > /dev/null
INI_JSON=$(checked_compose_exec "$COMPOSE_FILE" initiator \
    maknoon identity info default --json)
INITIATOR_ID=$(printf '%s' "$INI_JSON" | jq -r '.peer_id')
[ -z "$INITIATOR_ID" ] || [ "$INITIATOR_ID" = "null" ] && { echo "❌ Empty peer_id for initiator"; exit 1; }
echo "  - Initiator: $INITIATOR_ID"

# Step 2: Initiator sets up Institutional Vault
PEER_LIST=$(IFS=,; echo "${GUARDIAN_ADDRS[*]}")
echo "🔒 Initiator initializing institutional vault with peers: $PEER_LIST"

INIT_RES=$(checked_compose_exec "$COMPOSE_FILE" initiator \
    maknoon vault init-institutional mission-vault \
    --threshold 2 --shares 3 --peers "$PEER_LIST" --passphrase "TopSecretPass" --json)

SHARD1=$(printf '%s' "$INIT_RES" | jq -r '.shares[0]')
SHARD2=$(printf '%s' "$INIT_RES" | jq -r '.shares[1]')
SHARD3=$(printf '%s' "$INIT_RES" | jq -r '.shares[2]')
for s in "$SHARD1" "$SHARD2" "$SHARD3"; do
    [ -z "$s" ] || [ "$s" = "null" ] && { echo "❌ Null shard in init-institutional output"; exit 1; }
done

# Step 3: Distribute shards and setup policies on Guardians
echo "📤 Distributing shards and auto-approval policies..."

docker compose -f "$COMPOSE_FILE" cp initiator:/home/maknoon/.maknoon/keys/default.kem.pub initiator.kem.pub
docker compose -f "$COMPOSE_FILE" cp initiator:/home/maknoon/.maknoon/keys/default.sig.pub initiator.sig.pub

cat > policy.json <<EOF
{
  "name": "auto-approval",
  "rules": [
    { "type": "quorum", "action": "vault_unlock", "values": ["auto-approve:$INITIATOR_ID"] },
    { "type": "capability", "action": "allow", "values": ["p2p", "audit", "identity", "crypto"] }
  ]
}
EOF

SHARDS=("$SHARD1" "$SHARD2" "$SHARD3")
for j in {1..3}; do
    docker compose -f "$COMPOSE_FILE" cp policy.json "guardian-$j":/home/maknoon/policy.json
    docker compose -f "$COMPOSE_FILE" cp initiator.kem.pub "guardian-$j":/home/maknoon/initiator.kem.pub
    docker compose -f "$COMPOSE_FILE" cp initiator.sig.pub "guardian-$j":/home/maknoon/initiator.sig.pub

    checked_compose_exec "$COMPOSE_FILE" "guardian-$j" mkdir -p /home/maknoon/.maknoon/vaults
    docker compose -f "$COMPOSE_FILE" exec -T "guardian-$j" \
        sh -c "printf '%s' '${SHARDS[$((j-1))]}' > /home/maknoon/.maknoon/vaults/mission-vault.vault.shard_0.maknf"

    checked_compose_exec "$COMPOSE_FILE" "guardian-$j" \
        maknoon contact add initiator \
        --kem-pub /home/maknoon/initiator.kem.pub \
        --sig-pub /home/maknoon/initiator.sig.pub \
        --peer-id "$INITIATOR_ID"

    docker compose -f "$COMPOSE_FILE" exec -d "guardian-$j" \
        sh -c "maknoon tunnel listen --p2p --address :4000 --identity g${j} --policy /home/maknoon/policy.json > /home/maknoon/logs/guardian-${j}.log 2>&1"
done
rm -f policy.json initiator.kem.pub initiator.sig.pub

# Step 4: Initiator populates the vault
echo "📝 Populating institutional vault..."
checked_compose_exec "$COMPOSE_FILE" initiator \
    sh -c "MAKNOON_PASSWORD=RecoveredValue123 maknoon vault set intel-service -u agent-x --vault mission-vault --passphrase TopSecretPass"

# Wait for all guardians to be listening on port 4000
for j in {1..3}; do
    wait_for_condition "guardian-$j listening on :4000" 30 \
        docker compose -f "$COMPOSE_FILE" exec -T "guardian-$j" \
            sh -c "netstat -tln 2>/dev/null | grep ':4000 ' || ss -tln | grep ':4000 '"
done

# Step 5: THE CORE TEST - Automated Quorum Unlock
echo "🩹 ATTEMPTING AUTOMATED ORCHESTRATED UNLOCK (No passphrase provided)..."
GET_OUT=$(docker compose -f "$COMPOSE_FILE" exec -T initiator \
    maknoon vault get "intel-service" --vault mission-vault --json || echo "EXEC_FAILED")

assert_json_field "$GET_OUT" ".password" "RecoveredValue123"

print_result PASS "Orchestrated Quorum Unlocking verified — shards retrieved via P2P automatically"
echo "✅ SUCCESS: Orchestrated Quorum Unlocking verified!"

echo "🧹 Tearing down Orchestrated Mission..."
docker compose -f "$COMPOSE_FILE" down
