#!/bin/bash
set -e

# Mission 4: Dynamic Agility "Red-Team" Migration
# Verification of live configuration migration and cryptographic agility.

source "$(dirname "$0")/common.sh"
COMPOSE_FILE="deploy/docker/mission-agility.yml"

trap 'fail_trap "Dynamic Agility Migration" "$COMPOSE_FILE"' EXIT

generate_test_certs "deploy/docker/certs"

echo "🏗️  Provisioning Agility Mission Infrastructure..."
docker compose -f $COMPOSE_FILE up -d --build

# Wait for nodes to initialize
echo "⏳ Waiting for nodes to initialize..."
sleep 15

# Step 1: Verify early files are Profile 1 (ML-KEM)
echo "🛡️  Verifying Initial State (Profile 1: ML-KEM)..."
TRANSFORMER_CONTAINER=$(docker compose -f $COMPOSE_FILE ps -q transformer)

# Wait for some files to be encrypted
MAX_WAIT=30
WAITED=0
while ! docker exec $TRANSFORMER_CONTAINER sh -c "ls /home/maknoon/data/encrypted/*.makn >/dev/null 2>&1"; do
    if [ $WAITED -ge $MAX_WAIT ]; then
        echo "❌ TIMEOUT: No files were encrypted."
        docker compose -f $COMPOSE_FILE logs transformer
        exit 1
    fi
    sleep 1
    WAITED=$((WAITED+1))
done
sleep 5 # Let it process a few

FILE1=$(docker exec $TRANSFORMER_CONTAINER sh -c "ls /home/maknoon/data/encrypted/*.makn | head -n 1")
INFO1=$(docker exec $TRANSFORMER_CONTAINER maknoon info "$FILE1" --json)
P1=$(echo "$INFO1" | jq -r '.profile_id')

if [ "$P1" != "1" ]; then
    echo "❌ FAILED: Expected Profile 1, got $P1"
    exit 1
fi
echo "✅ Initial files confirmed as Profile 1 (ML-KEM)."

# Step 2: Controller triggers migration via MCP SSE
echo "🎯 CONTROLLER: Triggering Dynamic Migration to Profile 3 (Conservative/FrodoKEM)..."
CONTROLLER_CONTAINER=$(docker compose -f $COMPOSE_FILE ps -q controller)

# Establish session (TLS with self-signed cert — -k skips verify, same as --insecure on maknoon call)
docker exec -d $CONTROLLER_CONTAINER sh -c "curl -s -k -N https://transformer:8080/sse > /tmp/sse.log 2>&1"
sleep 5

# Extract message path (URL starts with https, grep matches since https contains 'http')
RAW_URL=$(docker exec $CONTROLLER_CONTAINER sh -c "grep 'data: http' /tmp/sse.log | head -n 1 | sed 's/data: //'")
MSG_PATH=$(echo "$RAW_URL" | sed 's|https://[^/]*||' | tr -d '\r\n')

if [ -z "$MSG_PATH" ]; then
    echo "❌ FAILED: MCP SSE session establishment failed."
    docker exec $CONTROLLER_CONTAINER sh -c "cat /tmp/sse.log"
    exit 1
fi

# Call config_update
docker exec $CONTROLLER_CONTAINER curl -s -k -X POST "https://transformer:8080$MSG_PATH" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "config_update",
      "arguments": {
        "profile_id": 3
      }
    },
    "id": 101
  }' > /dev/null

echo "⏳ Waiting for migration to propagate..."
sleep 15

# Step 3: Verify later files are Profile 3
echo "🛡️  Verifying Post-Migration State (Profile 3: Conservative/FrodoKEM)..."
# Look for the absolute NEWEST file
FILE2=$(docker exec $TRANSFORMER_CONTAINER sh -c "ls -t /home/maknoon/data/encrypted/*.makn | head -n 1")
INFO2=$(docker exec $TRANSFORMER_CONTAINER maknoon info "$FILE2" --json)
P2=$(echo "$INFO2" | jq -r '.profile_id')

if [ "$P2" != "3" ]; then
    echo "❌ FAILED: Migration failed! Expected Profile 3, still seeing $P2"
    exit 1
fi

echo "✅ SUCCESS: Dynamic Agility verified! Pipeline migrated from Profile 1 (ML-KEM) to Profile 3 (Conservative) without downtime."

echo "🧹 Tearing down Agility Mission..."
docker compose -f $COMPOSE_FILE down
