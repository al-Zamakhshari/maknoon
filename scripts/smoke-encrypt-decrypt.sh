#!/usr/bin/env bash
# Smoke: basic encrypt/decrypt round-trip
# The most fundamental maknoon operation — surprisingly only covered inside
# the Docker pipeline mission, not locally. Covers passphrase, compression,
# tamper detection, wrong key, and directory recursion.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

mission_start "smoke-encrypt-decrypt"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

export HOME="$TMP"

PLAINTEXT="maknoon post-quantum encrypt/decrypt smoke — $(date -u)"
echo "$PLAINTEXT" > "$TMP/input.txt"

# ── 1. Basic passphrase round-trip ────────────────────────────────────────────

./maknoon encrypt "$TMP/input.txt" -s smoke-pass -o "$TMP/enc.makn" --quiet
assert_file_exists "encrypt: output file created" "$TMP/enc.makn"

./maknoon decrypt "$TMP/enc.makn" -s smoke-pass -o "$TMP/dec.txt" --overwrite --quiet
RECOVERED=$(cat "$TMP/dec.txt")
assert_eq "decrypt: content matches original" "$PLAINTEXT" "$RECOVERED"

# ── 2. SHA-256 integrity after round-trip ────────────────────────────────────

assert_hashes_equal "round-trip: SHA-256 matches" "$TMP/input.txt" "$TMP/dec.txt"

# ── 3. Compressed encrypt/decrypt ────────────────────────────────────────────

./maknoon encrypt --compress "$TMP/input.txt" -s smoke-pass -o "$TMP/enc-compressed.makn" --quiet
assert_file_exists "compress+encrypt: output created" "$TMP/enc-compressed.makn"

./maknoon decrypt "$TMP/enc-compressed.makn" -s smoke-pass -o "$TMP/dec-compressed.txt" --overwrite --quiet
assert_hashes_equal "compress+decrypt: SHA-256 matches" "$TMP/input.txt" "$TMP/dec-compressed.txt"

# ── 4. Wrong passphrase is rejected ──────────────────────────────────────────

assert_exits_nonzero "wrong passphrase: decrypt fails" \
    ./maknoon decrypt "$TMP/enc.makn" -s wrong-pass -o "$TMP/nope.txt" --quiet

# ── 5. Tampered ciphertext is rejected ───────────────────────────────────────

cp "$TMP/enc.makn" "$TMP/tampered.makn"
# Flip the last byte of the file
python3 -c "
import sys
data = bytearray(open('$TMP/tampered.makn','rb').read())
data[-1] ^= 0xFF
open('$TMP/tampered.makn','wb').write(data)
" 2>/dev/null || printf '\xFF' >> "$TMP/tampered.makn"

assert_exits_nonzero "tampered file: decrypt fails" \
    ./maknoon decrypt "$TMP/tampered.makn" -s smoke-pass -o "$TMP/tampered-out.txt" --quiet

# ── 6. Directory encrypt/decrypt ─────────────────────────────────────────────

mkdir -p "$TMP/dir-in" "$TMP/dir-out"
echo "file-alpha" > "$TMP/dir-in/alpha.txt"
echo "file-beta"  > "$TMP/dir-in/beta.txt"
echo "file-gamma" > "$TMP/dir-in/gamma.txt"

./maknoon encrypt "$TMP/dir-in/" -s smoke-pass -r --quiet
# Decrypt all .makn files back to dir-out
./maknoon decrypt "$TMP/dir-in/" -s smoke-pass -r -o "$TMP/dir-out/" --overwrite --quiet

assert_exits_zero "dir decrypt: alpha recovered" \
    grep -qF "file-alpha" "$TMP/dir-out/alpha.txt"
assert_exits_zero "dir decrypt: beta recovered" \
    grep -qF "file-beta" "$TMP/dir-out/beta.txt"
assert_exits_zero "dir decrypt: gamma recovered" \
    grep -qF "file-gamma" "$TMP/dir-out/gamma.txt"

mission_end
