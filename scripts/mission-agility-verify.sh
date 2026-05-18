#!/bin/bash
set -euo pipefail

# Mission 4: Dynamic Agility "Red-Team" Migration
# Verification of live configuration migration and cryptographic agility.

source "$(dirname "$0")/common.sh"
COMPOSE_FILE="deploy/docker/mission-agility.yml"
MISSION_REPORT_FILE="${MISSION_REPORT_FILE:-./mission-reports/mission-agility-verify.jsonl}"
mkdir -p "$(dirname "$MISSION_REPORT_FILE")"

trap 'fail_trap "Dynamic Agility Migration" "$COMPOSE_FILE"' EXIT

generate_test_certs "deploy/docker/certs"

echo "🏗️  Provisioning Agility Mission Infrastructure..."
docker compose -f "$COMPOSE_FILE" up -d --build

TRANSFORMER_CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps -q transformer)
CONTROLLER_CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps -q controller)

# Wait for the transformer MCP SSE server to be ready
wait_for_condition "transformer MCP SSE ready" 180 \
    docker exec "$TRANSFORMER_CONTAINER" \
        sh -c "curl -sk -o /dev/null -w '%{http_code}' https://localhost:8080/sse | grep -q 200"

# Step 1: Wait for first encrypted files to appear, then verify Profile 1
echo "🛡️  Verifying Initial State (Profile 1: ML-KEM)..."
wait_for_condition "first encrypted files" 120 \
    docker exec "$TRANSFORMER_CONTAINER" \
        sh -c "ls /home/maknoon/data/encrypted/*.makn >/dev/null 2>&1"

FILE1=$(docker exec "$TRANSFORMER_CONTAINER" \
    sh -c "ls /home/maknoon/data/encrypted/*.makn | head -n 1")
INFO1=$(checked_exec "$TRANSFORMER_CONTAINER" maknoon info "$FILE1" --json)
assert_json_field "$INFO1" ".profile_id" "1"
echo "✅ Initial files confirmed as Profile 1 (ML-KEM)."

# Step 2: Controller triggers migration via MCP SSE
echo "🎯 CONTROLLER: Triggering Dynamic Migration to Profile 3 (Conservative/FrodoKEM)..."

docker exec -d "$CONTROLLER_CONTAINER" \
    sh -c "curl -s -k -N https://transformer:8080/sse > /tmp/sse.log 2>&1"

wait_for_condition "SSE session message path" 90 \
    docker exec "$CONTROLLER_CONTAINER" grep -q "data: http" /tmp/sse.log
RAW_URL=$(docker exec "$CONTROLLER_CONTAINER" \
    sh -c "grep 'data: http' /tmp/sse.log | head -n 1 | sed 's/data: //'")
MSG_PATH=$(printf '%s' "$RAW_URL" | sed 's|https://[^/]*||' | tr -d '\r\n')

if [ -z "$MSG_PATH" ]; then
    echo "❌ FAILED: MCP SSE session establishment failed."
    docker exec "$CONTROLLER_CONTAINER" cat /tmp/sse.log
    exit 1
fi

docker exec "$CONTROLLER_CONTAINER" curl -s -k -X POST "https://transformer:8080${MSG_PATH}" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"config_update","arguments":{"profile_id":3}},"id":101}' \
    > /dev/null

# Wait for migration to propagate — poll until a file with profile 3 appears
wait_for_condition "profile-3 file appears" 120 \
    docker exec "$TRANSFORMER_CONTAINER" sh -c \
        "ls -t /home/maknoon/data/encrypted/*.makn 2>/dev/null | head -n 1 | xargs -I{} maknoon info {} --json | jq -e '.profile_id == \"3\"'"

# Step 3: Verify latest file is Profile 3
echo "🛡️  Verifying Post-Migration State (Profile 3: Conservative/FrodoKEM)..."
FILE2=$(docker exec "$TRANSFORMER_CONTAINER" \
    sh -c "ls -t /home/maknoon/data/encrypted/*.makn | head -n 1")
INFO2=$(checked_exec "$TRANSFORMER_CONTAINER" maknoon info "$FILE2" --json)
assert_json_field "$INFO2" ".profile_id" "3"

print_result PASS "Dynamic Agility verified — pipeline migrated Profile 1 → 3 without downtime"
echo "✅ SUCCESS: Dynamic Agility verified!"

echo "🧹 Tearing down Agility Mission..."
docker compose -f "$COMPOSE_FILE" down
