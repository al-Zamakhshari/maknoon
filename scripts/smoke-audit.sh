#!/bin/bash

# Maknoon Mission Verification: Industrial Audit Hardening

# Setup clean environment
TEST_DIR=$(mktemp -d)
export HOME=$TEST_DIR
mkdir -p $HOME/.maknoon/keys
mkdir -p $HOME/.maknoon/vaults

LOG_FILE="$TEST_DIR/audit.json"
CONFIG_FILE="$HOME/.maknoon/config.json"

# 1. Verify SECURITY_WARNING for Insecure Tunnels
echo "🔍 Task 1: Verifying Insecure-Mode Warnings..."

# Create a dummy config with audit enabled
cat << EOC > $CONFIG_FILE
{
  "audit": {
    "enabled": true,
    "log_file": "$LOG_FILE"
  }
}
EOC

# Perform a guaranteed-to-log operation
echo "test" > "$TEST_DIR/test.txt"
./maknoon encrypt "$TEST_DIR/test.txt" -s "pass" --quiet

# Now try 'tunnel start' and check for warning
# We use --insecure flag
./maknoon tunnel start 127.0.0.1:9999 --insecure --json > /dev/null 2>&1 &
PID=$!
sleep 2
kill $PID 2>/dev/null

if grep -q "SECURITY_WARNING" "$LOG_FILE"; then
    echo "✅ Success: SECURITY_WARNING detected in audit log for insecure tunnel."
else
    echo "❌ Failure: SECURITY_WARNING missing from audit log."
    cat "$LOG_FILE"
    exit 1
fi

# 2. Verify Integrity-Protected (Signed) Logs
echo "🔍 Task 2: Verifying Integrity-Protected (Signed) Logs..."

# Generate a signing key for the audit logs
./maknoon keygen -o audit_signer -s "audit-pass" --quiet

# Update config to use the signing key
cat << EOC > $CONFIG_FILE
{
  "audit": {
    "enabled": true,
    "log_file": "$LOG_FILE",
    "signing_key": "$HOME/.maknoon/keys/audit_signer.sig.key"
  }
}
EOC

# Perform an operation to trigger a signed log entry
echo "mission-data" > "$TEST_DIR/input.txt"
export MAKNOON_PASSPHRASE="audit-pass"
./maknoon encrypt "$TEST_DIR/input.txt" -s "test-pass" --quiet

# Check if the signature field exists in the last log entry
# The signature is very long (ML-DSA-87), so we check for presence and minimal length
LAST_ENTRY=$(tail -n 1 "$LOG_FILE")
SIG_VALUE=$(echo "$LAST_ENTRY" | jq -r '.signature // empty')

if [ -n "$SIG_VALUE" ] && [ "${#SIG_VALUE}" -gt 100 ]; then
    echo "✅ Success: Cryptographic signature detected in audit log entry (${#SIG_VALUE} bytes)."
else
    echo "❌ Failure: Signature missing or malformed in audit log."
    echo "Last entry: $LAST_ENTRY"
    exit 1
fi

echo "🏆 Mission Accomplished: Industrial Audit Hardening Verified."
rm -rf "$TEST_DIR"
exit 0