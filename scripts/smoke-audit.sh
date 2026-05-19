#!/bin/bash
# Maknoon Smoke: Audit log basic verification

set -euo pipefail

TEST_DIR=$(mktemp -d)
export HOME=$TEST_DIR
mkdir -p "$HOME/.maknoon/keys" "$HOME/.maknoon/vaults"

LOG_FILE="$TEST_DIR/audit.json"

cat > "$HOME/.maknoon/config.json" << EOC
{
  "audit": {
    "enabled": true,
    "log_file": "$LOG_FILE"
  }
}
EOC

echo "test-data" > "$TEST_DIR/input.txt"
./maknoon encrypt "$TEST_DIR/input.txt" -s "test-pass" --quiet

if [ ! -f "$LOG_FILE" ] || [ ! -s "$LOG_FILE" ]; then
    echo "❌ Audit: no log entries written"
    rm -rf "$TEST_DIR"
    exit 1
fi

ACTION=$(tail -n 1 "$LOG_FILE" | jq -r '.action // empty')
if [ -z "$ACTION" ]; then
    echo "❌ Audit: log entry has no action field"
    tail -n 1 "$LOG_FILE"
    rm -rf "$TEST_DIR"
    exit 1
fi

echo "✅ Audit: log entry written (action=$ACTION)"
rm -rf "$TEST_DIR"
echo "✅ smoke-audit passed"
