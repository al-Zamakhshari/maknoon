#!/bin/bash
set -euo pipefail

# Mission 3: Threshold-Authorized "Dead Man's Switch"
# Verification of Distributed Multi-Sig Governance via P2P.

source "$(dirname "$0")/common.sh"
COMPOSE_FILE="deploy/docker/mission-deadmans.yml"
MISSION_REPORT_FILE="${MISSION_REPORT_FILE:-./mission-reports/mission-deadmans-verify.jsonl}"
mkdir -p "$(dirname "$MISSION_REPORT_FILE")"

trap 'fail_trap "Dead Man Switch" "$COMPOSE_FILE"' EXIT

echo "🏗️  Provisioning Dead Man's Switch Infrastructure..."
docker compose -f "$COMPOSE_FILE" up -d --build

# Wait for recovery-node identity to be ready
wait_for_condition "recovery-node identity ready" 60 \
    docker compose -f "$COMPOSE_FILE" exec -T recovery-node \
        test -f /home/maknoon/.maknoon/keys/recovery-id.kem.pub

# Step 1: Initialize SSS Shards on Recovery Node
echo "🎲 Recovery Node: Generating Master Secret and Shards (3-of-4)..."
RECOVERY_CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps -q recovery-node)
MASTER_SECRET="deadbeefdeadbeefdeadbeefdeadbeef"

SHARDS_JSON=$(checked_exec "$RECOVERY_CONTAINER" \
    maknoon identity shard "$MASTER_SECRET" -n 4 -m 3 --json)

# Extract and validate shards
SHARD1=$(printf '%s' "$SHARDS_JSON" | jq -r '.shares[0]')
SHARD2=$(printf '%s' "$SHARDS_JSON" | jq -r '.shares[1]')
SHARD3=$(printf '%s' "$SHARDS_JSON" | jq -r '.shares[2]')
SHARD4=$(printf '%s' "$SHARDS_JSON" | jq -r '.shares[3]')
for s in "$SHARD1" "$SHARD2" "$SHARD3" "$SHARD4"; do
    [ -z "$s" ] || [ "$s" = "null" ] && { echo "❌ Null shard in split output"; exit 1; }
done

# Step 2: Distribute shards to Guardians
echo "📡 Distributing Shards to Guardians..."
SHARDS=("$SHARD1" "$SHARD2" "$SHARD3" "$SHARD4")
for i in 1 2 3 4; do
    G_CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps -q "guardian-$i")
    printf '%s' "${SHARDS[$((i-1))]}" > "g${i}.shard"
    docker cp "g${i}.shard" "$G_CONTAINER":/home/maknoon/shard.txt
done

# Step 3: Secure the High-Value Asset on Recovery Node
echo "🔒 Recovery Node: Securing high-value asset in vault..."
checked_exec "$RECOVERY_CONTAINER" \
    sh -c "MAKNOON_PASSWORD=maknoon-gold-access maknoon vault set SECRET_SERVICE \
        --user ADMIN --vault top-secret --passphrase '$MASTER_SECRET'"

# Step 4: Trigger Recovery (3 guardians send shards)
echo "🆘 TRIGGERING RECOVERY: 3 Guardians transmitting shards..."
NET_QUORUM=$(docker network ls --filter name=quorum-net --format "{{.Name}}")
RECOVERY_IP=$(docker inspect -f \
    "{{with index .NetworkSettings.Networks \"$NET_QUORUM\"}}{{.IPAddress}}{{end}}" \
    "$RECOVERY_CONTAINER")

for i in 1 2 3; do
    echo "📡 Guardian $i sending shard..."
    docker exec "$RECOVERY_CONTAINER" sh -c \
        "timeout 30 maknoon receive --p2p --identity recovery-id --trace > shard_recv.log 2>&1" &
    RECV_PID=$!

    wait_for_condition "recovery-node listening for shard $i" 30 \
        docker exec "$RECOVERY_CONTAINER" grep -q "/ip4/$RECOVERY_IP" shard_recv.log
    RECOVERY_ADDR=$(docker exec "$RECOVERY_CONTAINER" \
        grep "/ip4/$RECOVERY_IP" shard_recv.log | grep "/tcp/" | tail -n 1 | awk '{print $NF}' | tr -d '\r')

    if [ -z "$RECOVERY_ADDR" ]; then
        echo "❌ FAILED: Could not find Recovery Multiaddr."
        exit 1
    fi

    G_CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps -q "guardian-$i")
    docker cp "$RECOVERY_CONTAINER":/home/maknoon/.maknoon/keys/recovery-id.kem.pub recovery.pub
    docker cp recovery.pub "$G_CONTAINER":/home/maknoon/recovery.pub

    checked_exec "$G_CONTAINER" \
        maknoon send shard.txt --to "$RECOVERY_ADDR" --public-key recovery.pub --identity "g${i}-id" --trace

    wait "$RECV_PID" || true

    RECEIVED_FILE=$(docker exec "$RECOVERY_CONTAINER" sh -c "ls shard.txt* 2>/dev/null | head -n 1")
    if [ -z "$RECEIVED_FILE" ]; then
        echo "❌ FAILED: Shard $i did not arrive."
        exit 1
    fi
    docker exec "$RECOVERY_CONTAINER" mv "$RECEIVED_FILE" "shard${i}.txt"
done

# Step 5: Recovery Node combines shards and unlocks
echo "🧩 Recovery Node: Reconstructing Master Secret..."
RECOV_SHARD1=$(checked_exec "$RECOVERY_CONTAINER" cat shard1.txt)
RECOV_SHARD2=$(checked_exec "$RECOVERY_CONTAINER" cat shard2.txt)
RECOV_SHARD3=$(checked_exec "$RECOVERY_CONTAINER" cat shard3.txt)

RECOV_MASTER_JSON=$(checked_exec "$RECOVERY_CONTAINER" \
    sh -c "maknoon identity reconstruct '$RECOV_SHARD1' '$RECOV_SHARD2' '$RECOV_SHARD3' --json")
RECOVERED_MASTER=$(printf '%s' "$RECOV_MASTER_JSON" | jq -r '.secret' | tr -d '\r' | xargs)

if [ "$MASTER_SECRET" != "$RECOVERED_MASTER" ]; then
    print_result FAIL "Master secret reconstruction failed: expected=$MASTER_SECRET got=$RECOVERED_MASTER"
    exit 1
fi

echo "🔓 Recovery Node: Unlocking vault with recovered secret..."
VAULT_JSON=$(checked_exec "$RECOVERY_CONTAINER" \
    maknoon vault get SECRET_SERVICE --vault top-secret --passphrase "$RECOVERED_MASTER" --json)
assert_json_field "$VAULT_JSON" ".password" "maknoon-gold-access"

print_result PASS "Dead Man's Switch verified — master secret recovered via 3-of-4 P2P shards"
echo "✅ SUCCESS: Dead Man's Switch verified!"

echo "🧹 Tearing down..."
docker compose -f "$COMPOSE_FILE" down
rm -f shards.json g1.shard g2.shard g3.shard g4.shard recovery.pub
