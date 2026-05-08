#!/bin/bash
set -e

# Smoke Test: Maknoon PQC Dispersal & Threshold Orchestration (MCP & API)
# Verification of Phase 6/7 primitives via high-level orchestration layers.

source "$(dirname "$0")/common.sh"

echo "🏗️  Scaffolding Orchestration Smoke Suite..."
TMP_DIR=$(mktemp -d)
cleanup() {
    echo "🧹 Tearing down..."
    kill $API_PID 2>/dev/null || true
    if [ -d "$TMP_DIR" ]; then
        # Go modules are read-only, need +w to remove
        chmod -R +w "$TMP_DIR" 2>/dev/null || true
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

# Build binary once outside the restricted HOME
go build -o "$TMP_DIR/maknoon" ./cmd/maknoon

export HOME="$TMP_DIR"
CERT_DIR="$TMP_DIR/certs"
mkdir -p "$CERT_DIR"
generate_test_certs "$CERT_DIR"

# 1. Start Maknoon API Server
echo "🚀 Starting Maknoon PQC API Server..."
"$TMP_DIR/maknoon" serve --address :8081 --tls-cert "$CERT_DIR/server.crt" --tls-key "$CERT_DIR/server.key" > "$TMP_DIR/api.log" 2>&1 &
API_PID=$!

# Wait for server
for i in {1..10}; do
    if curl -k -s https://localhost:8081/v1/health > /dev/null; then
        echo "✅ API Server is UP."
        break
    fi
    if [ $i -eq 10 ]; then
        echo "❌ FAILED: API Server did not start."
        cat "$TMP_DIR/api.log"
        exit 1
    fi
    sleep 1
done

# 🆔 Generate identities for threshold test
echo "🆔 Generating Identities..."
"$TMP_DIR/maknoon" keygen -o alpha --no-password --quiet
"$TMP_DIR/maknoon" keygen -o beta --no-password --quiet
"$TMP_DIR/maknoon" keygen -o gamma --no-password --quiet

echo "📝 Preparing mission payload..."
echo "AL-ZAMAKHSHARI-PROJECT-MAKNOON-ORCHESTRATION-VERIFIED" > "$TMP_DIR/mission.txt"

# ------------------------------------------------------------------------------
# API DISPERSAL TEST
# ------------------------------------------------------------------------------
echo -e "\n🌐 Scenario: API-Driven Data Dispersal"

# Step 1: Fragment via API
echo "✂️  Fragmenting payload via REST API..."
FRAG_RES=$(curl -k -s -X POST https://localhost:8081/v1/crypto/fragment \
  -H "Content-Type: application/json" \
  -d "{\"input\":\"$TMP_DIR/mission.txt\", \"output\":\"$TMP_DIR/fragments\", \"data_shards\":2, \"parity_shards\":1}")

if echo "$FRAG_RES" | grep -q '"status":"success"'; then
    echo "✅ API Fragment Passed."
else
    echo "❌ API Fragment FAILED: $FRAG_RES"
    cat "$TMP_DIR/api.log"
    exit 1
fi

# Step 2: Sabotage and Reassemble via API
echo "🧨 Sabotaging fragment and reassembling via REST API..."
rm "$TMP_DIR/fragments/shard_000.maknf"
REASM_RES=$(curl -k -s -X POST https://localhost:8081/v1/crypto/reassemble \
  -H "Content-Type: application/json" \
  -d "{\"input_dir\":\"$TMP_DIR/fragments\", \"output\":\"$TMP_DIR/restored_api.txt\"}")

if echo "$REASM_RES" | grep -q '"status":"success"'; then
    echo "✅ API Reassemble Passed."
    RECOVERED=$(cat "$TMP_DIR/restored_api.txt")
    if [ "$RECOVERED" == "AL-ZAMAKHSHARI-PROJECT-MAKNOON-ORCHESTRATION-VERIFIED" ]; then
        echo "✅ Data Integrity Verified."
    else
        echo "❌ Data Mismatch: $RECOVERED"
        exit 1
    fi
else
    echo "❌ API Reassemble FAILED: $REASM_RES"
    cat "$TMP_DIR/api.log"
    exit 1
fi

# ------------------------------------------------------------------------------
# API THRESHOLD TEST
# ------------------------------------------------------------------------------
echo -e "\n🔒 Scenario: API-Driven Threshold Quorum"

# Step 1: Sign with 2 keys
echo "✍️  Signing with Alpha and Beta..."
cp "$TMP_DIR/mission.txt" "$TMP_DIR/mission_alpha.txt"
cp "$TMP_DIR/mission.txt" "$TMP_DIR/mission_beta.txt"

"$TMP_DIR/maknoon" sign "$TMP_DIR/mission_alpha.txt" -k alpha.sig.key
"$TMP_DIR/maknoon" sign "$TMP_DIR/mission_beta.txt" -k beta.sig.key

SIG_A_BASE64=$(base64 < "$TMP_DIR/mission_alpha.txt.sig" | tr -d '\n')
SIG_B_BASE64=$(base64 < "$TMP_DIR/mission_beta.txt.sig" | tr -d '\n')

# Step 2: Aggregate via API
echo "📦 Aggregating signatures via REST API..."
AGG_RES=$(curl -k -s -X POST https://localhost:8081/v1/identity/sign/aggregate \
  -H "Content-Type: application/json" \
  -d "{\"signatures\":[\"$SIG_A_BASE64\", \"$SIG_B_BASE64\"]}")

AGG_SIG_B64=$(echo "$AGG_RES" | jq -r '.signature' | tr -d '\n')

# Step 3: Verify Threshold via API
echo "🧪 Verifying 2-of-3 threshold via REST API..."
PUB_A_B64=$(base64 < "$TMP_DIR/.maknoon/keys/alpha.sig.pub" | tr -d '\n')
PUB_B_B64=$(base64 < "$TMP_DIR/.maknoon/keys/beta.sig.pub" | tr -d '\n')
PUB_G_B64=$(base64 < "$TMP_DIR/.maknoon/keys/gamma.sig.pub" | tr -d '\n')
DATA_B64=$(base64 < "$TMP_DIR/mission.txt" | tr -d '\n')

VERIFY_RES=$(curl -k -s -X POST https://localhost:8081/v1/identity/verify \
  -H "Content-Type: application/json" \
  -d "{
    \"data\":\"$DATA_B64\", 
    \"signature\":\"$AGG_SIG_B64\", 
    \"public_keys\":[\"$PUB_A_B64\", \"$PUB_B_B64\", \"$PUB_G_B64\"],
    \"threshold\":2
  }")

if echo "$VERIFY_RES" | grep -q '"valid":true'; then
    echo "✅ API Threshold Verification Passed."
else
    echo "❌ API Threshold Verification FAILED: $VERIFY_RES"
    cat "$TMP_DIR/api.log"
    exit 1
fi

# ------------------------------------------------------------------------------
# MCP DISPERSAL TEST (Local Stdio)
# ------------------------------------------------------------------------------
echo -e "\n🤖 Scenario: MCP-Driven Data Dispersal (Stdio)"

MCP_FRAG_RES=$(echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"fragment_file","arguments":{"input":"'"$TMP_DIR/mission.txt"'","output":"'"$TMP_DIR/mcp_fragments"'","data_shards":2,"parity_shards":1}},"id":1}' | "$TMP_DIR/maknoon" mcp --transport stdio 2>/dev/null | grep '"id":1')

if echo "$MCP_FRAG_RES" | grep -q "status.*success"; then
    echo "✅ MCP Fragment Tool Passed."
else
    echo "❌ MCP Fragment Tool FAILED: $MCP_FRAG_RES"
    exit 1
fi

echo -e "\n🏆 SUCCESS: Maknoon Orchestration Smoke Suite (API & MCP) Verified."
