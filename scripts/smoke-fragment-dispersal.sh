#!/bin/bash
set -e

# Smoke Test: PQC Fragmented Dispersal & Retrieval
# Verifies RAID-for-Privacy (Phase 7) primitives

echo "🏗️  Scaffolding PQC Dispersal Smoke Suite..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

export HOME="$TMP_DIR"
./maknoon keygen -o alpha --no-password --quiet
./maknoon keygen -o beta --no-password --quiet
./maknoon keygen -o gamma --no-password --quiet

echo "📝 Preparing mission payload..."
echo "AL-ZAMAKHSHARI-PROJECT-MAKNOON-DISPERSAL-VERIFIED" > "$TMP_DIR/mission.txt"

# Step 1: Fragmented Dispersal
echo "✂️  Fragmenting and dispersing payload (2 data + 1 parity)..."
mkdir -p "$TMP_DIR/fragments"
./maknoon fragment "$TMP_DIR/mission.txt" -d 2 -r 1 -o "$TMP_DIR/fragments/"

# Verify fragments exist
if [ ! -f "$TMP_DIR/fragments/shard_000.maknf" ] || [ ! -f "$TMP_DIR/fragments/shard_002.maknf" ]; then
    echo "❌ FAILED: Fragments not generated."
    exit 1
fi

# Step 2: Sabotage a shard (Simulate failure/loss)
echo "🧨 Sabotaging Shard 0 (Simulating data loss)..."
rm "$TMP_DIR/fragments/shard_000.maknf"

# Step 3: Reassemble from remaining shards
echo "🩹 Reassembling from remaining shards..."
./maknoon reassemble "$TMP_DIR/fragments/" -o "$TMP_DIR/restored.txt"

# Verify content
RECOVERED=$(cat "$TMP_DIR/restored.txt")
if [ "$RECOVERED" == "AL-ZAMAKHSHARI-PROJECT-MAKNOON-DISPERSAL-VERIFIED" ]; then
    echo "✅ SUCCESS: Fragment reassembly verified after 33% data loss."
else
    echo "❌ FAILED: Data mismatch or corruption."
    echo "Got: $RECOVERED"
    exit 1
fi

# Step 4: Integrity Verification (Anti-Pollution)
echo "🛡️  Verifying Forensic Integrity (Anti-Pollution)..."
# Re-fragment with signing
./maknoon keygen -o signer --no-password --quiet
./maknoon fragment "$TMP_DIR/mission.txt" -d 2 -r 1 --sign-with signer.sig.key -o "$TMP_DIR/fragments_signed/"

# Corrupt a shard by overwriting part of the signature/data
# 16 bytes header + some offset
echo "CORRUPTED_DATA_TRIPWIRE" | dd of="$TMP_DIR/fragments_signed/shard_001.maknf" bs=1 seek=50 conv=notrunc 2>/dev/null

echo "🔍 Attempting reassemble on corrupted signed fragments..."
# We MUST provide the public key for verification
if ./maknoon reassemble "$TMP_DIR/fragments_signed/" --authorized-key "$TMP_DIR/.maknoon/keys/signer.sig.pub" -o "$TMP_DIR/wont_happen.txt" 2>&1 | grep -q "integrity failure"; then
    echo "✅ SUCCESS: Integrity failure detected correctly."
else
    echo "❌ FAILED: Accepted corrupted shard!"
    # Print fragment info for debugging
    ls -l "$TMP_DIR/fragments_signed/"
    exit 1
fi

echo "✨ PQC Dispersal Smoke Suite Passed!"
