---
name: maknoon
description: >
  Post-quantum cryptographic operations for files, vaults, and identities.
  Use when you need to encrypt or decrypt files with PQC hybrid encryption
  (ML-KEM-768 + X25519), manage encrypted vaults, sign or verify files with
  ML-DSA-87, generate PQC keypairs, fragment files into erasure-coded shards
  for distributed storage (compose with rclone), or publish/resolve PQC
  identities via WKD or DNS. Also use when the user mentions .makn files,
  quantum-resistant encryption, post-quantum keys, or secure secret storage.
license: MIT
compatibility: >
  Requires the maknoon binary (brew install al-Zamakhshari/tap/maknoon or
  download from https://github.com/al-Zamakhshari/maknoon/releases).
  MCP server launched automatically in stdio mode.
metadata:
  mcp-command: maknoon mcp --transport stdio
  mcp-env: MAKNOON_AGENT_MODE=1
allowed-tools: Bash(maknoon:*)
---

# Maknoon — Post-Quantum Cryptography

Maknoon is a PQC crypto engine with 45 MCP tools across six categories.
Always use `maknoon schema` (not `--help`) to get structured JSON of all commands.

## Environment

Set before every operation:
- `MAKNOON_AGENT_MODE=1` — activates AgentPolicy (sandbox, structured output)
- `MAKNOON_PASSPHRASE` — vault and key unlock passphrase (never pass on CLI)
- `MAKNOON_JSON=1` — forces JSON output for all commands

## Core operations

### Encrypt / Decrypt

```bash
# Single recipient
maknoon encrypt report.pdf -o report.pdf.makn

# Multi-recipient (petname, @handle, or key path — comma-separated)
maknoon encrypt report.pdf -p @alice@corp.com -p @bob@corp.com -o report.pdf.makn

# Decrypt
maknoon decrypt report.pdf.makn -o report.pdf
```

Use `maknoon info <file>` to inspect a .makn header without decrypting.

### Keys and identities

```bash
maknoon keygen alice --no-password    # generate ML-KEM+ML-DSA keypair
maknoon identity active               # list local identities
maknoon identity publish @alice@example.com --wkd    # publish via HTTPS
maknoon identity publish @alice@example.com --dns    # publish via DNS TXT
```

### Contacts (trusted petnames)

```bash
maknoon contact add @alice --kem-pub alice.kem.pub --sig-pub alice.sig.pub
maknoon contact list
maknoon contact remove @alice
```

Use petnames with `encrypt -p @alice` or `verify -p @alice` instead of raw key paths.

### Vault (encrypted secrets)

```bash
maknoon vault set github-token --vault default   # prompts for value
maknoon vault get github-token --vault default
maknoon vault list --vault default
maknoon vault export --vault default -o backup.vault.makn
maknoon vault import --vault recovered -i backup.vault.makn
```

Use MCP tools `vault_set_blob` / `vault_get_blob` for encrypted agent memory.

### Sign / Verify

```bash
maknoon sign report.pdf -k alice.sig.key        # → report.pdf.sig
maknoon verify report.pdf -p alice.sig.pub      # single key
maknoon verify report.pdf -p alice.sig.pub -p bob.sig.pub --threshold 2
```

### Fragment + rclone (RAID-for-Privacy)

Fragment a file into erasure-coded shards, then distribute with rclone:

```bash
maknoon fragment secret.makn --data 5 --parity 3 \
  --output /tmp/shards/ --output-manifest ~/manifests/secret.json

rclone sync /tmp/shards/ s3:bucket/shards/
maknoon shred /tmp/shards/

# Recovery
rclone copy s3:bucket/shards/ /tmp/recover/
cp ~/manifests/secret.json /tmp/recover/manifest.json
maknoon reassemble /tmp/recover/ --output secret.makn --verify
```

### Session keys (bulk encryption)

Derive once, reuse across many files to skip the 26ms/file Argon2id cost:

```bash
KEY=$(maknoon session derive -s "$MAKNOON_PASSPHRASE")
maknoon encrypt file1.pdf --session-key "$KEY"
maknoon encrypt file2.pdf --session-key "$KEY"
```

## MCP tools (45 total)

Categories: `crypto` · `vault` · `identity` · `dispersal` · `config` · `profiles`

Key tools:
- `encrypt_file` / `decrypt_file` — PQC file encryption (multi-recipient, directory support)
- `vault_get` / `vault_set` / `vault_set_blob` / `vault_get_blob` — secrets + agent memory
- `fragment_file` / `reassemble_file` — erasure coding with rclone hint
- `shred_file` — secure deletion (multi-pass overwrite + rename)
- `audit_verify` — verify hash-chain integrity of audit log
- `vault_status` / `vault_check_shards` — quorum vault health
- `diagnostic` — full engine manifest (call first to orient)

## Security rules

- Never pass passphrases or keys as CLI arguments — use environment variables
- Private key bytes are held in memguard-locked buffers and zeroed after use
- All file paths are validated against path-traversal; stay within `~/.maknoon/` and `/tmp/`
- `MAKNOON_AGENT_MODE=1` enforces AgentPolicy: restricted paths, no vault delete

## Audit

All cryptographic operations are logged with SHA-256 hash chaining and ML-DSA-87 signatures:

```bash
maknoon audit export     # view operation history
maknoon audit verify     # verify log integrity (detect tampering)
```
