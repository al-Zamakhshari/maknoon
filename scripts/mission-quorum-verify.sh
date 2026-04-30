#!/bin/bash
set -e

# Mission: Threshold Quorum (Phase 2)
# Verification of Distributed Key Resilience

source "$(dirname "$0")/common.sh"
COMPOSE_FILE="deploy/docker/mission-quorum.yml"

trap 'fail_trap "Threshold Quorum" "$COMPOSE_FILE"' EXIT

echo "🏗️  Provisioning Threshold Quorum Mesh..."
docker compose -f $COMPOSE_FILE up -d --build

# Wait for Guardians to generate IDs
echo "📡 Waiting for Guardians to broadcast Multiaddrs..."
MAX_RETRIES=30
declare -a GUARDIAN_ADDRS
for j in {1..4}; do
    ADDR=""
    for i in $(seq 1 $MAX_RETRIES); do
        ADDR=$(docker compose -f $COMPOSE_FILE logs guardian-$j | grep "/ip4/" | grep -v "127.0.0.1" | head -n 1 | awk '{print $NF}' | tr -d '\r')
        if [ ! -z "$ADDR" ]; then
            GUARDIAN_ADDRS+=("$ADDR")
            break
        fi
        sleep 1
    done
    if [ -z "$ADDR" ]; then
        echo "❌ FAILED: Could not retrieve Guardian-$j Multiaddr."
        exit 1
    fi
    echo "🆔 Guardian-$j Identity Found: $ADDR"
done

# Step 1: Generate Master Key on Recovery Node
echo "🔑 Generating Master Secret on Recovery Node..."
docker compose -f $COMPOSE_FILE exec recovery-node sh -c \
    "MAKNOON_PASSWORD=SuperSecret123 maknoon vault set MASTER_SECRET"

# Step 2: Split Vault into 3-of-4 shards
echo "✂️  Splitting Vault into 3-of-4 shards..."
# We need to provide the passphrase to split
SHARDS_JSON=$(docker compose -f $COMPOSE_FILE exec recovery-node maknoon vault split -s quorum-pass --json --shares 4 --threshold 3)
echo "💎 Shards generated."

# Step 3: Distribute shards and vault file to Guardians
for i in {0..3}; do
    # Extract i-th shard from .shares array
    SHARD=$(echo $SHARDS_JSON | jq -r ".shares[$i]")
    j=$((i+1))
    echo "📤 Distributing shard $j and vault to Guardian-$j..."
    docker compose -f $COMPOSE_FILE exec guardian-$j sh -c "echo '$SHARD' > /home/maknoon/shard.txt"
    docker compose -f $COMPOSE_FILE cp recovery-node:/home/maknoon/.maknoon/vaults/default.vault .
    docker compose -f $COMPOSE_FILE cp default.vault guardian-$j:/home/maknoon/.maknoon/vaults/default.vault
    docker compose -f $COMPOSE_FILE exec -u root guardian-$j chown 1000:1000 /home/maknoon/.maknoon/vaults/default.vault
done
rm default.vault

# Step 4: Wipe Master Vault on Recovery Node
echo "🧨 Wiping local vault on Recovery Node..."
docker compose -f $COMPOSE_FILE exec recovery-node rm -rf /home/maknoon/.maknoon/vaults/default.vault

sleep 2

# Step 5: Simulate failure (Kill one guardian)
echo "💀 Killing Guardian-4 (Simulating node failure)..."
docker compose -f $COMPOSE_FILE stop guardian-4

# Step 6: Recover from remaining 3 guardians
echo "🩹 Attempting recovery from 3 remaining guardians..."
RECOVERED_SHARDS=""
for j in {1..3}; do
    S=$(docker compose -f $COMPOSE_FILE exec guardian-$j cat /home/maknoon/shard.txt)
    RECOVERED_SHARDS="$RECOVERED_SHARDS '$S'"
done

# Recover into a NEW vault file 'recovered.vault'
# We need to tell it WHICH vault to recover from (it needs a salt)
# Let's use the vault from Guardian-1
docker compose -f $COMPOSE_FILE cp guardian-1:/home/maknoon/.maknoon/vaults/default.vault .
docker compose -f $COMPOSE_FILE cp default.vault recovery-node:/home/maknoon/.maknoon/vaults/default.vault
docker compose -f $COMPOSE_FILE exec -u root recovery-node chown 1000:1000 /home/maknoon/.maknoon/vaults/default.vault
rm default.vault

docker compose -f $COMPOSE_FILE exec recovery-node sh -c \
    "maknoon vault recover -o recovered $RECOVERED_SHARDS"

# Step 7: Verify Secret
echo "🧪 Verifying recovered secret integrity..."
# Use the new vault
FINAL_SECRET=$(docker compose -f $COMPOSE_FILE exec recovery-node maknoon vault get MASTER_SECRET -v recovered --json | jq -r '.password')


if [ "$FINAL_SECRET" == "SuperSecret123" ]; then
    echo "✅ SUCCESS: Threshold Quorum verified! Master secret recovered from 3-of-4 nodes."
else
    echo "❌ FAILED: Secret recovery failed or corrupted."
    echo "Got: $FINAL_SECRET"
    exit 1
fi

echo "🧹 Tearing down Quorum..."
docker compose -f $COMPOSE_FILE down
