#!/bin/bash
set -e

# Smoke Test: Threshold Multi-Signatures (ML-DSA)
# Verifies Institutional Trust (Phase 6.1) primitives

echo "🏗️  Scaffolding Threshold Signature Smoke Suite..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

export HOME="$TMP_DIR"

# 1. Generate 3 Identities
echo "🆔 Generating Identities (Alpha, Beta, Gamma)..."
./maknoon keygen -o alpha --no-password --quiet
./maknoon keygen -o beta --no-password --quiet
./maknoon keygen -o gamma --no-password --quiet

# 2. Prepare Payload
echo "📝 Preparing Payload..."
echo "MISSION-APPROVAL-X-99" > "$TMP_DIR/payload.txt"

# 3. Sign independently
echo "✍️  Signing with 3 independent keys..."
./maknoon sign "$TMP_DIR/payload.txt" -k alpha.sig.key
mv "$TMP_DIR/payload.txt.sig" "$TMP_DIR/alpha.sig"

./maknoon sign "$TMP_DIR/payload.txt" -k beta.sig.key
mv "$TMP_DIR/payload.txt.sig" "$TMP_DIR/beta.sig"

./maknoon sign "$TMP_DIR/payload.txt" -k gamma.sig.key
mv "$TMP_DIR/payload.txt.sig" "$TMP_DIR/gamma.sig"

# 4. Aggregate
echo "📦 Aggregating into multi-sig..."
./maknoon sign aggregate "$TMP_DIR/alpha.sig" "$TMP_DIR/beta.sig" "$TMP_DIR/gamma.sig" -o "$TMP_DIR/multi.sig"

# 5. Verify Thresholds
echo "🧪 Verifying 3-of-3 quorum..."
PUB_KEYS="alpha.sig.pub,beta.sig.pub,gamma.sig.pub"
if ./maknoon verify "$TMP_DIR/payload.txt" --signature "$TMP_DIR/multi.sig" --public-key "$PUB_KEYS" --threshold 3 | grep -q "Verified"; then
    echo "✅ SUCCESS: 3-of-3 quorum verified."
else
    echo "❌ FAILED: 3-of-3 quorum rejected!"
    exit 1
fi

echo "🧪 Verifying 2-of-3 quorum..."
if ./maknoon verify "$TMP_DIR/payload.txt" --signature "$TMP_DIR/multi.sig" --public-key "$PUB_KEYS" --threshold 2 | grep -q "Verified"; then
    echo "✅ SUCCESS: 2-of-3 quorum verified."
else
    echo "❌ FAILED: 2-of-3 quorum rejected!"
    exit 1
fi

echo "🧪 Verifying failure on impossible quorum (4-of-3)..."
if ./maknoon verify "$TMP_DIR/payload.txt" --signature "$TMP_DIR/multi.sig" --public-key "$PUB_KEYS" --threshold 4 2>&1 | grep -q "FAILED"; then
    echo "✅ SUCCESS: 4-of-3 quorum failed as expected."
else
    echo "❌ FAILED: Accepted 4-of-3 quorum with only 3 signatures!"
    exit 1
fi

echo "✨ Threshold Signature Smoke Suite Passed!"
