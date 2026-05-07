#!/bin/bash

# Maknoon Mission Verification: Vault Safety (Phase 3)

echo "🧪 Starting Mission: Vault Safety Verification..."

# Setup clean environment
TEST_DIR=$(mktemp -d)
export HOME=$TEST_DIR
mkdir -p $HOME/.maknoon/keys
mkdir -p $HOME/.maknoon/vaults

LOG_FILE="$TEST_DIR/audit.json"
CONFIG_FILE="$HOME/.maknoon/config.json"

cat << EOC > $CONFIG_FILE
{
  "audit": {
    "enabled": true,
    "log_file": "$LOG_FILE"
  }
}
EOC

# 1. Verify In-Place Passphrase Rotation
echo "🔍 Task 1: Verifying In-Place Passphrase Rotation..."

# Create entry with old passphrase
export MAKNOON_PASSPHRASE="old-secret"
export MAKNOON_PASSWORD="pqc-rocks"
./maknoon vault set "my-service" -u "ahmed" --vault "safety-test" --overwrite

# Verify we can get it
./maknoon vault get "my-service" --vault "safety-test" --json | grep -q "pqc-rocks"
if [ $? -eq 0 ]; then
    echo "✅ Entry stored and retrieved correctly with old passphrase."
else
    echo "❌ Failure: Could not retrieve entry."
    exit 1
fi

# Rotate to new passphrase
echo "🔄 Rotating vault passphrase..."
unset MAKNOON_PASSPHRASE
(echo "old-secret"; echo "new-secret"; echo "new-secret") | ./maknoon vault rotate --vault "safety-test"

# Verify we can get it with NEW passphrase
echo "🔍 Verifying with NEW passphrase..."
export MAKNOON_PASSPHRASE="new-secret"
./maknoon vault get "my-service" --vault "safety-test" --json > "$TEST_DIR/get-new.json" 2>&1
if grep -q "pqc-rocks" "$TEST_DIR/get-new.json"; then
    echo "✅ Success: Vault rotated! Retrieved entry with NEW passphrase."
else
    echo "❌ Failure: Could not retrieve entry after rotation with NEW passphrase."
    cat "$TEST_DIR/get-new.json"
    exit 1
fi

# Verify old passphrase fails
echo "🔍 Verifying OLD passphrase fails..."
export MAKNOON_PASSPHRASE="old-secret"
./maknoon vault get "my-service" --vault "safety-test" --json > "$TEST_DIR/get-old.json" 2>&1
if grep -q "authentication failed" "$TEST_DIR/get-old.json"; then
    echo "✅ Success: OLD passphrase correctly rejected."
else
    echo "❌ Failure: OLD passphrase still works!"
    echo "Result for OLD passphrase:"
    cat "$TEST_DIR/get-old.json"
    exit 1
fi

# 2. Verify Sharding Health Check
echo "🔍 Task 2: Verifying Sharding Health Check..."

export MAKNOON_PASSPHRASE="new-secret"
SHARDS_JSON=$(./maknoon vault split --vault "safety-test" --threshold 2 --shares 3 --json)
SHARD1=$(echo "$SHARDS_JSON" | jq -r '.shares[0]')
SHARD2=$(echo "$SHARDS_JSON" | jq -r '.shares[1]')

# Check shards
./maknoon vault check-shards "$SHARD1" "$SHARD2" --json | grep -q "Validated 2 healthy shards"
if [ $? -eq 0 ]; then
    echo "✅ Success: Validated healthy shards correctly."
else
    echo "❌ Failure: Healthy shards validation failed."
    ./maknoon vault check-shards "$SHARD1" "$SHARD2" --json
    exit 1
fi

# Verify corruption detection
CORRUPT_SHARD=$(echo "$SHARD1" | awk '{$NF="abandon"; print}')

echo "🛡️  Testing corruption detection..."
./maknoon vault check-shards "$CORRUPT_SHARD" "$SHARD2" --json 2>&1 | grep -q "checksum mismatch"
if [ $? -eq 0 ]; then
    echo "✅ Success: Corrupt shard detected correctly."
else
    echo "❌ Failure: Corruption went undetected."
    ./maknoon vault check-shards "$CORRUPT_SHARD" "$SHARD2" --json
    exit 1
fi

echo "🏆 Mission Accomplished: Vault Safety Verified."
rm -rf "$TEST_DIR"
exit 0