#!/bin/bash
set -euo pipefail

# Mission: Threshold Quorum (Phase 2)
# Verification of Distributed Key Resilience

source "$(dirname "$0")/common.sh"
COMPOSE_FILE="deploy/docker/mission-quorum.yml"
MISSION_REPORT_FILE="${MISSION_REPORT_FILE:-./mission-reports/mission-quorum-verify.jsonl}"
mkdir -p "$(dirname "$MISSION_REPORT_FILE")"

trap 'fail_trap "Threshold Quorum" "$COMPOSE_FILE"' EXIT

echo "🏗️  Provisioning Threshold Quorum Mesh..."
docker compose -f "$COMPOSE_FILE" up -d --build

# Wait for all guardians to write their identity key file
for j in {1..4}; do
    wait_for_condition "guardian-$j identity ready" 120 \
        docker compose -f "$COMPOSE_FILE" exec -T "guardian-$j" \
            test -f /home/maknoon/.maknoon/keys/g${j}.kem.pub
    echo "🆔 Guardian-$j identity confirmed"
done

# Step 1: Generate Master Key on Recovery Node
echo "🔑 Generating Master Secret on Recovery Node..."
checked_compose_exec "$COMPOSE_FILE" recovery-node \
    sh -c "MAKNOON_PASSWORD=SuperSecret123 maknoon vault set MASTER_SECRET"

# Step 2: Split Vault into 3-of-4 shards
echo "✂️  Splitting Vault into 3-of-4 shards..."
SHARDS_JSON=$(checked_compose_exec "$COMPOSE_FILE" recovery-node \
    maknoon vault split -s quorum-pass --json --shares 4 --threshold 3)
echo "💎 Shards generated."

# Step 3: Distribute shards and vault file to Guardians
for i in {0..3}; do
    SHARD=$(printf '%s' "$SHARDS_JSON" | jq -r ".shares[$i]")
    [ -z "$SHARD" ] || [ "$SHARD" = "null" ] && { echo "❌ Shard $i is null"; exit 1; }
    j=$((i + 1))
    echo "📤 Distributing shard $j and vault to Guardian-$j..."
    docker compose -f "$COMPOSE_FILE" exec -T "guardian-$j" sh -c "printf '%s' '$SHARD' > /home/maknoon/shard.txt"
    docker compose -f "$COMPOSE_FILE" cp recovery-node:/home/maknoon/.maknoon/vaults/default.vault .
    docker compose -f "$COMPOSE_FILE" cp default.vault "guardian-$j":/home/maknoon/.maknoon/vaults/default.vault
    docker compose -f "$COMPOSE_FILE" exec -T -u root "guardian-$j" chown 1000:1000 /home/maknoon/.maknoon/vaults/default.vault
done
rm -f default.vault

# Step 4: Wipe Master Vault on Recovery Node
echo "🧨 Wiping local vault on Recovery Node..."
checked_compose_exec "$COMPOSE_FILE" recovery-node \
    rm -rf /home/maknoon/.maknoon/vaults/default.vault

# Step 5: Simulate failure (Kill one guardian)
echo "💀 Killing Guardian-4 (Simulating node failure)..."
docker compose -f "$COMPOSE_FILE" stop guardian-4

# Step 6: Recover from remaining 3 guardians
echo "🩹 Attempting recovery from 3 remaining guardians..."
RECOVERED_SHARDS=""
for j in {1..3}; do
    S=$(checked_compose_exec "$COMPOSE_FILE" "guardian-$j" cat /home/maknoon/shard.txt)
    RECOVERED_SHARDS="$RECOVERED_SHARDS '$S'"
done

# Copy vault from Guardian-1 to recovery node
docker compose -f "$COMPOSE_FILE" cp guardian-1:/home/maknoon/.maknoon/vaults/default.vault .
docker compose -f "$COMPOSE_FILE" cp default.vault recovery-node:/home/maknoon/.maknoon/vaults/default.vault
docker compose -f "$COMPOSE_FILE" exec -T -u root recovery-node chown 1000:1000 /home/maknoon/.maknoon/vaults/default.vault
rm -f default.vault

checked_compose_exec "$COMPOSE_FILE" recovery-node \
    sh -c "maknoon vault recover -o recovered $RECOVERED_SHARDS"

# Step 7: Verify Secret
echo "🧪 Verifying recovered secret integrity..."
SECRET_JSON=$(checked_compose_exec "$COMPOSE_FILE" recovery-node \
    maknoon vault get MASTER_SECRET -v recovered -s quorum-pass --json)
assert_json_field "$SECRET_JSON" ".password" "SuperSecret123"

print_result PASS "Threshold Quorum verified — master secret recovered from 3-of-4 nodes"
echo "✅ SUCCESS: Threshold Quorum verified!"

echo "🧹 Tearing down Quorum..."
docker compose -f "$COMPOSE_FILE" down
