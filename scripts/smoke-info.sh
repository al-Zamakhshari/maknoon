#!/usr/bin/env bash
# Smoke: maknoon info — file metadata inspection
# Completely untested before this script.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

mission_start "smoke-info"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

export HOME="$TMP"

echo "inspect-me" > "$TMP/input.txt"

# ── 1. Text output on a standard encrypted file ───────────────────────────────

./maknoon encrypt "$TMP/input.txt" -s info-pass -o "$TMP/enc.makn" --quiet
assert_file_exists "setup: encrypted file exists" "$TMP/enc.makn"

text_out=$(./maknoon info "$TMP/enc.makn" 2>&1)
assert_contains "info text: shows Symmetric" "Symmetric" "$text_out"
assert_contains "info text: shows Compression field" "Compression" "$text_out"

# ── 2. JSON output fields ─────────────────────────────────────────────────────

json_out=$(./maknoon --json info "$TMP/enc.makn" 2>&1)

# Validate it is parseable JSON
if echo "$json_out" | jq . >/dev/null 2>&1; then
    pass "info --json: output is valid JSON"
else
    fail "info --json: output is not valid JSON"
fi

assert_json_output "info --json: .type is symmetric" "$json_out" ".type" "symmetric"
assert_json_output "info --json: .compressed is false (no --compress)" "$json_out" ".compressed" "false"

# ── 3. Compressed file reports compressed=true ────────────────────────────────

./maknoon encrypt --compress "$TMP/input.txt" -s info-pass -o "$TMP/enc-c.makn" --quiet

compressed_text=$(./maknoon info "$TMP/enc-c.makn" 2>&1)
assert_contains "compressed info text: Compression: true" "true" "$compressed_text"

compressed_json=$(./maknoon --json info "$TMP/enc-c.makn" 2>&1)
assert_json_output "compressed info --json: .compressed is true" "$compressed_json" ".compressed" "true"

# ── 4. Non-.makn file is rejected ────────────────────────────────────────────

assert_exits_nonzero "info on plain text file fails" \
    ./maknoon info "$TMP/input.txt"

assert_exits_nonzero "info on non-existent file fails" \
    ./maknoon info "$TMP/does-not-exist.makn"

# ── 5. Identity-encrypted file shows asymmetric type ─────────────────────────

./maknoon keygen -o smoke-id --no-password --quiet 2>/dev/null || \
    ./maknoon keygen -o smoke-id --no-password 2>/dev/null
PUB_KEY=$(find "$TMP" -name "smoke-id.kem.pub" 2>/dev/null | head -1)

if [ -n "$PUB_KEY" ]; then
    ./maknoon encrypt "$TMP/input.txt" -p "$PUB_KEY" -o "$TMP/enc-asym.makn" --quiet
    asym_json=$(./maknoon --json info "$TMP/enc-asym.makn" 2>&1)
    assert_json_output "asymmetric info --json: .type is asymmetric" "$asym_json" ".type" "asymmetric"
else
    fail "setup: could not find public key for asymmetric test"
fi

mission_end
