#!/bin/bash
set -e

# Mission: Automated Governance Audit
# Verifies high-fidelity observability and forensic auditing capabilities.

source "$(dirname "$0")/common.sh"
COMPOSE_FILE="deploy/docker/mcp.yml"

trap 'fail_trap "Governance Audit" "$COMPOSE_FILE"' EXIT

echo "🏗️  Provisioning Governance Audit Infrastructure..."
docker compose -p maknoon -f $COMPOSE_FILE up -d --build
sleep 15

# Use sender container for local operations
CONTAINER="sender"
EXEC="docker compose -p maknoon -f $COMPOSE_FILE exec -T $CONTAINER"

echo "🔑 Provisioning PQC Identity..."
$EXEC maknoon keygen -o audit-agent --no-password --profile nist

echo "⚙️  Enabling Audit Logging..."
$EXEC maknoon config set audit.enabled true

echo "📂 Step 1: Performing sensitive operation (Encryption)..."
echo "Top Secret Data" > top-secret.txt
docker cp top-secret.txt $(docker compose -p maknoon -f deploy/docker/mcp.yml ps -q sender):/home/maknoon/top-secret.txt
$EXEC maknoon encrypt top-secret.txt -s "agent-pass" -o top-secret.makn

echo "🔍 Step 2: Verifying Audit Export (Forensics)..."
# Audit export should pick up the 'protect' action from the log file
AUDIT_JSON=$($EXEC maknoon audit export --json)


# Assert that the 'protect' action was recorded
if ! echo "$AUDIT_JSON" | jq -e '.[] | select(.action == "protect")' > /dev/null; then
    echo "❌ FAILED: 'protect' action missing from audit log."
    echo "Audit Log: $AUDIT_JSON"
    exit 1
fi
echo "✅ Audit: 'protect' action found."

# Assert that input path is masked/recorded
if ! echo "$AUDIT_JSON" | jq -e '.[] | select(.action == "protect") | .metadata.input == "top-secret.txt"' > /dev/null; then
    echo "❌ FAILED: Input filename incorrectly recorded or missing in metadata."
    exit 1
fi
echo "✅ Audit: Metadata integrity verified."

echo "🖥️  Step 3: Verifying System Diagnostics (State Manifest)..."
DIAG_JSON=$($EXEC maknoon diag --json)

# Assert Engine State
ACTIVE_POLICY=$(echo "$DIAG_JSON" | jq -r '.engine.active_policy')
if [ "$ACTIVE_POLICY" != "human" ]; then
    echo "❌ FAILED: Unexpected active policy: $ACTIVE_POLICY"
    exit 1
fi
echo "✅ Diag: Active policy verified ($ACTIVE_POLICY)."

# Assert Performance Defaults
DEFAULT_PROFILE=$(echo "$DIAG_JSON" | jq -r '.performance.default_profile')
if [ "$DEFAULT_PROFILE" != "1" ]; then
    echo "❌ FAILED: Unexpected default profile ID: $DEFAULT_PROFILE"
    exit 1
fi
echo "✅ Diag: Performance defaults verified."

echo "🛡️ Step 4: Verifying Identity Integrity via JSON..."
ID_INFO=$($EXEC maknoon identity info audit-agent --json)
PEER_ID=$(echo "$ID_INFO" | jq -r '.peer_id')

if [[ ! "$PEER_ID" =~ ^12D3KooW ]]; then
    echo "❌ FAILED: Invalid PeerID format in identity info."
    echo "Got: $PEER_ID"
    exit 1
fi
echo "✅ Identity: PeerID verified ($PEER_ID)."

echo -e "\n🏆 SUCCESS: Automated Governance Audit Mission Passed."
echo "Verified: Audit Export, System Diagnostics, and Identity Metadata Parity."

echo "🧹 Tearing down..."
docker compose -p maknoon -f $COMPOSE_FILE down
rm top-secret.txt
