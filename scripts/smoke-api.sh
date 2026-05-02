#!/bin/bash
set -e

# Smoke Test: Maknoon PQC API Server + BadgerDB Backend
# Verification of RESTful PQC services and server-grade storage.

source "$(dirname "$0")/common.sh"

export MAKNOON_AUDIT_ENABLED=1
export MAKNOON_AUDIT_LOG_FILE="tmp/audit.log"

echo "🏗️  Preparing API Smoke Test..."
CERT_DIR="tmp/api-certs"
generate_test_certs "$CERT_DIR"

# Ensure binary is built
go build -o maknoon ./cmd/maknoon

# 1. Start Maknoon API Server with BadgerDB
echo "🚀 Starting Maknoon PQC API Server (BadgerDB)..."
./maknoon serve --address :8081 --tls-cert "$CERT_DIR/server.crt" --tls-key "$CERT_DIR/server.key" --backend badger > api.log 2>&1 &
API_PID=$!

# Cleanup on exit
trap "kill $API_PID || true; rm -rf $CERT_DIR maknoon api.log" EXIT

# Wait for server to be ready
echo "⏳ Waiting for API to become active..."
sleep 5

# 2. Test Health Endpoint
echo "🏥 Testing Health Endpoint..."
HEALTH=$(curl -k -s https://localhost:8081/v1/health)
if echo "$HEALTH" | grep -q '"status":"pass"'; then
    echo "✅ Health Check Passed."
else
    echo "❌ Health Check FAILED: $HEALTH"
    cat api.log
    exit 1
fi

# 3. Test Vault Set (via API)
echo "🔒 Testing Vault Set (REST)..."
SET_RES=$(curl -k -s -X POST https://localhost:8081/v1/vault/set \
  -H "Content-Type: application/json" \
  -d '{"vault":"api-test", "service":"github", "username":"alice", "password":"secret-password", "passphrase":"master-pass", "overwrite":true}')

if echo "$SET_RES" | grep -q '"status":"success"'; then
    echo "✅ Vault Set Passed."
else
    echo "❌ Vault Set FAILED: $SET_RES"
    cat api.log
    exit 1
fi

# 4. Test Vault Get (via API)
echo "🔑 Testing Vault Get (REST)..."
GET_RES=$(curl -k -s -X POST https://localhost:8081/v1/vault/get \
  -H "Content-Type: application/json" \
  -d '{"vault":"api-test", "service":"github", "passphrase":"master-pass"}')

# Note: SecretBytes ([]byte) is base64 encoded in JSON
if echo "$GET_RES" | grep -q '"username":"alice"' && echo "$GET_RES" | grep -q '"password":"c2VjcmV0LXBhc3N3b3Jk"'; then
    echo "✅ Vault Get Passed (Correct Credential Retrieved)."
else
    echo "❌ Vault Get FAILED: $GET_RES"
    cat api.log
    exit 1
fi

# 5. Test Audit Export (via API)
echo "🛡️  Testing Audit Export (REST)..."
AUDIT_RES=$(curl -k -s https://localhost:8081/v1/audit/export)
if echo "$AUDIT_RES" | grep -q '"action"'; then
    echo "✅ Audit Export Passed (Logs Retrieved)."
else
    echo "❌ Audit Export FAILED: $AUDIT_RES"
    cat api.log
    exit 1
fi

# 6. Test Identity Resolution (via API)
echo "🌍 Testing Identity Resolution (REST)..."
# First, create an identity to resolve
./maknoon keygen -o api-id --no-password
# Get the hex public key
HEX_PUB=$(./maknoon identity info api-id --json | jq -r '.kem_pub')
# Resolve via hex
RESOLVE_RES=$(curl -k -s "https://localhost:8081/v1/identity/resolve?handle=$HEX_PUB")
if echo "$RESOLVE_RES" | grep -q "$HEX_PUB"; then
    echo "✅ Identity Resolution Passed (Hex)."
else
    echo "❌ Identity Resolution FAILED: $RESOLVE_RES"
    cat api.log
    exit 1
fi

# 7. Test Envelope Encryption (Wrap/Unwrap via API)
echo "📦 Testing Envelope Encryption (Wrap/Unwrap)..."
# Extract public key from api-id (hex)
HEX_PUB=$(./maknoon identity info api-id --json | jq -r '.kem_pub')
WRAP_RES=$(curl -k -s -X POST https://localhost:8081/v1/crypto/wrap \
  -H "Content-Type: application/json" \
  -d "{\"public_key\":\"$HEX_PUB\"}")

WRAPPED_KEY_HEX=$(echo "$WRAP_RES" | jq -r '.wrapped')
PLAINTEXT_DEK_HEX=$(echo "$WRAP_RES" | jq -r '.plaintext')

echo "   DEK (Plaintext): $PLAINTEXT_DEK_HEX"
echo "   DEK (Wrapped):   ${WRAPPED_KEY_HEX:0:32}..."

if [ -n "$WRAPPED_KEY_HEX" ] && [ "$WRAPPED_KEY_HEX" != "null" ]; then
    echo "✅ KMS Wrap Passed (Hex)."
else
    echo "❌ KMS Wrap FAILED: $WRAP_RES"
    cat api.log
    exit 1
fi

# Unwrap to verify
UNWRAP_RES=$(curl -k -s -X POST https://localhost:8081/v1/crypto/unwrap \
  -H "Content-Type: application/json" \
  -d "{\"wrapped_key\":\"$WRAPPED_KEY_HEX\", \"key_path\":\"api-id\", \"passphrase\":\"\"}")

UNWRAPPED_DEK_HEX=$(echo "$UNWRAP_RES" | jq -r '.plaintext')

if [ "$UNWRAPPED_DEK_HEX" == "$PLAINTEXT_DEK_HEX" ]; then
    echo "✅ KMS Unwrap Passed (DEK Restored via Hex)."
else
    echo "❌ KMS Unwrap FAILED: $UNWRAP_RES (Expected $PLAINTEXT_DEK_HEX)"
    cat api.log
    exit 1
fi

# 8. Test Tunnel Orchestration (via API)
echo "🌉 Testing Tunnel Orchestration (REST)..."
# Just test the endpoint accepts the call (status/stop)
STOP_RES=$(curl -k -s -X POST https://localhost:8081/v1/network/tunnel/stop)
if echo "$STOP_RES" | grep -q '"status":"stopped"'; then
    echo "✅ Tunnel Stop Passed."
else
    echo "❌ Tunnel Stop FAILED: $STOP_RES"
    cat api.log
    exit 1
fi

# 9. Verify Badger Storage Persistence (via CLI)
echo "📂 Verifying Badger Persistence via CLI..."
# We need to point to the same vaults directory. 
# By default it's ~/.maknoon/vaults. 
# The server created 'api-test.vault' directory (Badger).
CLI_RES=$(./maknoon vault get github --vault api-test --passphrase master-pass --backend badger --json)
if echo "$CLI_RES" | grep -q '"username": "alice"'; then
    echo "✅ CLI-to-API Interoperability Verified (Badger Backend)."
else
    echo "❌ CLI Retrieval FAILED: $CLI_RES"
    cat api.log
    exit 1
fi

echo -e "\n🏆 SUCCESS: Maknoon API Server & BadgerDB Verified."
