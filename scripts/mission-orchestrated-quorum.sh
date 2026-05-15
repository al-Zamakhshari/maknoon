#!/bin/bash
set -e

# Mission: Orchestrated Quorum Unlocking (Phase 6.2)
# Verification of Automated P2P-based Vault Access

source "$(dirname "$0")/common.sh"
COMPOSE_FILE="deploy/docker/mission-orchestrated.yml"

trap 'fail_trap "Orchestrated Quorum" "$COMPOSE_FILE"' EXIT

echo "🏗️  Provisioning Orchestrated Quorum Mesh..."
docker compose -f $COMPOSE_FILE up -d --build

# Step 1: Generate Identities and Extract Multiaddrs
echo "🆔 Generating Identities..."
declare -a GUARDIAN_ADDRS

for j in {1..3}; do
    docker compose -f $COMPOSE_FILE exec guardian-$j maknoon keygen --no-password -o g$j > /dev/null
    ID=$(docker compose -f $COMPOSE_FILE exec guardian-$j maknoon identity info g$j --json | jq -r '.peer_id')
    IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' docker-guardian-$j-1)
    ADDR="/ip4/$IP/tcp/4000/p2p/$ID"
    GUARDIAN_ADDRS+=("$ADDR")
    echo "  - Guardian-$j: $ADDR"
done

INITIATOR_ID=$(docker compose -f $COMPOSE_FILE exec initiator maknoon keygen --no-password -o default > /dev/null && \
               docker compose -f $COMPOSE_FILE exec initiator maknoon identity info default --json | jq -r '.peer_id')
echo "  - Initiator: $INITIATOR_ID"

# Step 2: Initiator sets up Institutional Vault
PEER_LIST=$(IFS=,; echo "${GUARDIAN_ADDRS[*]}")
echo "🔒 Initiator initializing institutional vault with peers: $PEER_LIST"

INIT_RES=$(docker compose -f $COMPOSE_FILE exec initiator maknoon vault init-institutional mission-vault \
    --threshold 2 --shares 3 --peers "$PEER_LIST" --passphrase "TopSecretPass" --json)

# Extract shards for distribution
SHARD1=$(echo "$INIT_RES" | jq -r '.shares[0]')
SHARD2=$(echo "$INIT_RES" | jq -r '.shares[1]')
SHARD3=$(echo "$INIT_RES" | jq -r '.shares[2]')

# Step 3: Distribute shards and setup policies on Guardians
echo "📤 Distributing shards and auto-approval policies..."

# Pre-extract initiator's public keys to host for distribution
docker compose -f $COMPOSE_FILE cp initiator:/home/maknoon/.maknoon/keys/default.kem.pub ./initiator.kem.pub
docker compose -f $COMPOSE_FILE cp initiator:/home/maknoon/.maknoon/keys/default.sig.pub ./initiator.sig.pub

cat > policy.json <<EOF
{
  "name": "auto-approval",
  "rules": [
    { "type": "quorum", "action": "vault_unlock", "values": ["auto-approve:$INITIATOR_ID"] },
    { "type": "capability", "action": "allow", "values": ["p2p", "audit"] }
  ]
}
EOF

for j in {1..3}; do
    SHARD_VAR="SHARD$j"
    docker compose -f $COMPOSE_FILE cp policy.json guardian-$j:/home/maknoon/policy.json
    docker compose -f $COMPOSE_FILE cp initiator.kem.pub guardian-$j:/home/maknoon/initiator.kem.pub
    docker compose -f $COMPOSE_FILE cp initiator.sig.pub guardian-$j:/home/maknoon/initiator.sig.pub

    docker compose -f $COMPOSE_FILE exec guardian-$j mkdir -p /home/maknoon/.maknoon/vaults
    docker compose -f $COMPOSE_FILE exec guardian-$j sh -c "echo '${!SHARD_VAR}' > /home/maknoon/.maknoon/vaults/mission-vault.shard_0.maknf"

    # Add Initiator to Guardian's contacts for signature verification
    docker compose -f $COMPOSE_FILE exec guardian-$j maknoon contact add initiator \
        --kem-pub /home/maknoon/initiator.kem.pub \
        --sig-pub /home/maknoon/initiator.sig.pub \
        --peer-id "$INITIATOR_ID"

    # Start the P2P listeners on Guardians in the background and redirect output to a log file
    docker compose -f $COMPOSE_FILE exec -d guardian-$j sh -c \
        "MAKNOON_DEFAULT_IDENTITY=g$j maknoon tunnel listen --p2p --address 0.0.0.0:4000 --identity g$j --policy /home/maknoon/policy.json"
done
rm policy.json initiator.kem.pub initiator.sig.pub

# Step 4: Initiator populates the vault
echo "📝 Populating institutional vault..."
docker compose -f $COMPOSE_FILE exec initiator sh -c \
    "MAKNOON_PASSWORD=RecoveredValue123 maknoon vault set intel-service -u agent-x --vault mission-vault --passphrase TopSecretPass"

# Step 5: THE CORE TEST - Automated Quorum Unlock
echo "🩹 ATTEMPTING AUTOMATED ORCHESTRATED UNLOCK (No passphrase provided)..."
# Capture full output for debugging
GET_OUT=$(docker compose -f $COMPOSE_FILE exec initiator maknoon vault get "intel-service" --vault mission-vault --json || echo "EXEC_FAILED")
RECOVERED_VAL=$(echo "$GET_OUT" | jq -r '.password' 2>/dev/null || echo "JQ_FAILED")

if [ "$RECOVERED_VAL" == "RecoveredValue123" ]; then
    echo "✅ SUCCESS: Orchestrated Quorum Unlocking verified! Shards retrieved via P2P automatically."
else
    echo "❌ FAILED: Automated recovery failed."
    echo "Initiator Output: $GET_OUT"
    # Dump logs from Guardians
    docker compose -f $COMPOSE_FILE logs
    exit 1
fi

echo "🧹 Tearing down Orchestrated Mission..."
docker compose -f $COMPOSE_FILE down
