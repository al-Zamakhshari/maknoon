# Fragment Distribution with Rclone

> **Maknoon + Rclone: RAID-for-Privacy across cloud providers**

Maknoon handles erasure coding and cryptographic integrity. Rclone handles cloud distribution. Neither tool needs to know the other exists — they compose cleanly via the filesystem.

---

## How it works

```
maknoon encrypt secret.pdf          →  secret.pdf.makn   (PQC encrypted)
maknoon fragment secret.pdf.makn    →  8 shards + manifest.json
rclone copy shards/ remote:bucket/  →  distributed across cloud(s)
maknoon shred shards/               →  local copies securely deleted
```

Any 5 of the 8 shards reconstruct the original. No single cloud provider sees
enough to reconstruct the plaintext — even if your encryption key is compromised,
they still only have an incomplete erasure-coded ciphertext.

---

## Prerequisites

```bash
# Install rclone
brew install rclone          # macOS
curl https://rclone.org/install.sh | sudo bash  # Linux

# Configure your cloud remotes
rclone config
```

---

## Basic workflow

### 1. Encrypt and fragment

```bash
# Encrypt
maknoon encrypt contract.pdf -o contract.pdf.makn

# Fragment: 5 data shards + 3 parity (any 5 of 8 reconstruct)
maknoon fragment contract.pdf.makn \
  --data 5 --parity 3 \
  --output /tmp/shards/
```

This creates:
```
/tmp/shards/
  shard_000.maknf  ...  shard_007.maknf   (8 shard files)
  manifest.json                           (metadata + SHA-256 hash)
```

### 2. Distribute shards

Spread shards across different providers so no single party can reconstruct:

```bash
# Upload all shards + manifest to primary provider
rclone sync /tmp/shards/ s3:my-bucket/contract-shards/

# Upload subset to a second provider (parity shards for redundancy)
rclone copy /tmp/shards/shard_005.maknf gcs:backup-bucket/contract-shards/
rclone copy /tmp/shards/shard_006.maknf gcs:backup-bucket/contract-shards/
rclone copy /tmp/shards/shard_007.maknf gcs:backup-bucket/contract-shards/

# Shred local copies — nothing sensitive remains on disk
maknoon shred /tmp/shards/
```

### 3. Recover

```bash
# Fetch shards back (any 5 of 8 suffice)
mkdir /tmp/recover/
rclone copy s3:my-bucket/contract-shards/ /tmp/recover/

# Reassemble and verify SHA-256 against manifest
maknoon reassemble /tmp/recover/ \
  --output contract.pdf.makn \
  --verify

# Decrypt
maknoon decrypt contract.pdf.makn -o contract.pdf

# Clean up
maknoon shred /tmp/recover/
```

---

## Separating the manifest from the shards

The manifest records the shard count, original SHA-256, and metadata. By default
it lives alongside the shards. Use `--output-manifest` to store it separately —
useful when you want to upload shards to a cloud provider but keep the manifest
in a local vault or password manager:

```bash
maknoon fragment contract.pdf.makn \
  --data 5 --parity 3 \
  --output /tmp/shards/ \
  --output-manifest ~/.local/manifests/contract.json

# Now upload shards only — manifest is not included
rclone sync /tmp/shards/ s3:my-bucket/contract-shards/

# Store the manifest in Maknoon vault for safe keeping
maknoon vault set contract-manifest --vault default
# (paste the manifest JSON as the value, or encrypt it separately)
```

To recover later, you need to provide the manifest location:

```bash
# Fetch shards
rclone copy s3:my-bucket/contract-shards/ /tmp/recover/

# Copy manifest back so reassemble can find it
cp ~/.local/manifests/contract.json /tmp/recover/manifest.json

maknoon reassemble /tmp/recover/ --output contract.pdf.makn --verify
```

---

## Distributing across multiple providers (maximum privacy)

For maximum privacy, spread individual shards across providers that don't
share infrastructure or jurisdiction:

```bash
maknoon fragment classified.makn --data 5 --parity 3 -o /tmp/shards/

# Each shard to a different provider
rclone copy /tmp/shards/shard_000.maknf aws:bucket/
rclone copy /tmp/shards/shard_001.maknf aws:bucket/
rclone copy /tmp/shards/shard_002.maknf gcs:bucket/
rclone copy /tmp/shards/shard_003.maknf azure:container/
rclone copy /tmp/shards/shard_004.maknf b2:bucket/
rclone copy /tmp/shards/shard_005.maknf sftp:server/backup/
rclone copy /tmp/shards/shard_006.maknf dropbox:shards/
rclone copy /tmp/shards/shard_007.maknf gdrive:shards/
rclone copy /tmp/shards/manifest.json   aws:bucket/  # manifest anywhere

maknoon shred /tmp/shards/
```

No single provider has enough shards (5 needed, each has at most 2). An adversary
would need simultaneous access to five different providers across different
jurisdictions to reconstruct anything — and they'd still only get the encrypted
`.makn` file.

---

## Convenience shell wrapper

Save as `~/bin/makn-disperse`:

```bash
#!/bin/bash
# Usage: makn-disperse <file> <rclone-remote:path> [data_shards] [parity_shards]
set -euo pipefail

FILE="$1"
REMOTE="$2"
DATA="${3:-5}"
PARITY="${4:-3}"
TMPDIR="$(mktemp -d)"
MANIFEST="$HOME/.local/maknoon-manifests/$(basename "$FILE").manifest.json"

mkdir -p "$(dirname "$MANIFEST")"

echo "🔐 Encrypting..."
maknoon encrypt "$FILE" -o "$TMPDIR/$(basename "$FILE").makn"

echo "✂️  Fragmenting ($DATA data + $PARITY parity)..."
maknoon fragment "$TMPDIR/$(basename "$FILE").makn" \
  --data "$DATA" --parity "$PARITY" \
  --output "$TMPDIR/shards/" \
  --output-manifest "$MANIFEST"

echo "☁️  Uploading shards to $REMOTE..."
rclone sync "$TMPDIR/shards/" "$REMOTE"

echo "🗑️  Shredding local copies..."
maknoon shred "$TMPDIR/"

echo "✅ Done. Manifest saved to: $MANIFEST"
echo "   Recover with: makn-recover $MANIFEST $REMOTE"
```

And `~/bin/makn-recover`:

```bash
#!/bin/bash
# Usage: makn-recover <manifest> <rclone-remote:path> [output-file]
set -euo pipefail

MANIFEST="$1"
REMOTE="$2"
TMPDIR="$(mktemp -d)"

echo "☁️  Fetching shards from $REMOTE..."
rclone sync "$REMOTE" "$TMPDIR/shards/"
cp "$MANIFEST" "$TMPDIR/shards/manifest.json"

ORIGINAL_NAME=$(python3 -c "import json,sys; print(json.load(open('$MANIFEST'))['original_name'])" 2>/dev/null || echo "restored.data")
OUTPUT="${3:-$ORIGINAL_NAME}"

echo "🔧 Reassembling..."
maknoon reassemble "$TMPDIR/shards/" --output "$TMPDIR/$ORIGINAL_NAME" --verify

echo "🔓 Decrypting..."
maknoon decrypt "$TMPDIR/$ORIGINAL_NAME" -o "$OUTPUT"

maknoon shred "$TMPDIR/"
echo "✅ Recovered: $OUTPUT"
```

---

## Adding rclone encryption (double-encryption)

Rclone supports its own encryption layer (`rclone crypt`). Combined with Maknoon:

1. **Maknoon** encrypts the file with PQC (ML-KEM + AES-256-GCM)
2. **Rclone crypt** re-encrypts the shards at rest with XSalsa20 + Poly1305

```bash
# Configure rclone crypt remote wrapping your S3 remote
rclone config
# → New remote → name: s3-encrypted → type: crypt → remote: s3:bucket/shards

# Now upload through the crypt layer
rclone sync /tmp/shards/ s3-encrypted:
```

This is defense in depth: even if Maknoon's encryption were broken, the storage
layer has independent encryption. And even if rclone's encryption were broken,
the storage layer only has incomplete erasure-coded fragments.

---

## MCP agent workflow

Agents can orchestrate the full pipeline via MCP tools:

```json
// Fragment with separate manifest
{"tool": "fragment_file",
 "input": "/data/secret.makn",
 "output_dir": "/tmp/shards",
 "output_manifest": "/vault/manifests/secret.json",
 "data_shards": 5, "parity_shards": 3}

// After rclone upload (handled outside MCP):
// rclone sync /tmp/shards/ remote:bucket/

// Reassemble with verification
{"tool": "reassemble_file",
 "src_dir": "/tmp/recover",
 "output": "/data/secret.makn",
 "verify": true}
```

The `rclone_hint` field in the `fragment_file` response provides the exact
rclone command to run for the generated shard directory.
