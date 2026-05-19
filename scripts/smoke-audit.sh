#!/bin/bash
# Maknoon Smoke: Audit log integrity verification

set -euo pipefail

TEST_DIR=$(mktemp -d)
export HOME=$TEST_DIR
mkdir -p $HOME/.maknoon/keys $HOME/.maknoon/vaults

LOG_FILE="$TEST_DIR/audit.json"

# Configure audit with signing
./maknoon keygen -o audit_signer -s "audit-pass" --quiet

cat > "$HOME/.maknoon/config.json" << EOC
{
  "audit": {
    "enabled": true,
    "log_file": "$LOG_FILE",
    "signing_key": "$HOME/.maknoon/keys/audit_signer.sig.key"
  }
}
EOC

echo "test-data" > "$TEST_DIR/input.txt"
./maknoon encrypt "$TEST_DIR/input.txt" -s "test-pass" --quiet

LAST_ENTRY=$(tail -n 1 "$LOG_FILE")
SIG_VALUE=$(echo "$LAST_ENTRY" | jq -r '.signature // empty')

if [ -n "$SIG_VALUE" ] && [ "${#SIG_VALUE}" -gt 100 ]; then
    echo "✅ Audit: cryptographic signature present (${#SIG_VALUE} chars)"
else
    echo "❌ Audit: signature missing or malformed"
    echo "Last entry: $LAST_ENTRY"
    rm -rf "$TEST_DIR"
    exit 1
fi

rm -rf "$TEST_DIR"
echo "✅ smoke-audit passed"
