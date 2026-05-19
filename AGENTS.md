# Maknoon — Agent Instructions

Maknoon is a post-quantum cryptographic engine and MCP gateway. A single
statically-linked binary (~12 MB stripped) hosts the CLI and the native MCP server.

---

## Current Architecture

| Layer | Description |
|---|---|
| **CLI** | Cobra commands in `cmd/maknoon/commands/` |
| **MCP server** | 45 tools over stdio or SSE; registered in `mcp_*.go` |
| **Engine** | `pkg/crypto/Engine` — all business logic; CLI/MCP are thin controllers |
| **Vault** | bbolt-backed encrypted KV store; Argon2id key derivation |
| **Identity registry** | WKD (HTTPS static file, primary) → DNS TXT records |
| **Crypto kernel** | ML-KEM-768 + X25519 hybrid KEM; ML-DSA-87 signatures; AES-256-GCM |

**What was removed (do not reference these):**
P2P tunnel, libp2p DHT, BEP-44, FIDO2, Badger backend, OTEL, WorkspaceService,
AES-GCM-SIV, Nostr identity registry (`go-nostr` dep removed entirely),
full REST API (only `/v1/health`, `/v1/live`, `/v1/ready` probes remain).

---

## Cryptographic Stack

- **Symmetric:** AES-256-GCM (AEAD) — only cipher in use
- **KEM:** ML-KEM-768 + X25519 (X-Wing, Profile 1 / NIST). Conservative: FrodoKEM-640 (Profile 3)
- **Signatures:** ML-DSA-87 (primary); SLH-DSA-SHA2-128f (Profile 3 conservative)
- **KDF:** Argon2id (3 iterations, 64 MB memory, 4 threads by default)
- **Transport:** TLS 1.3 with X25519MLKEM768 hybrid for SSE mode
- **Key fingerprint:** `"mk" + hex(sha256(sigPub)[:8])` — stored as `peer_id` in contacts

**Profiles:**
| ID | Name | KEM | SIG |
|---|---|---|---|
| 1 | `nist` | ML-KEM-768 + X25519 | ML-DSA-87 |
| 3 | `conservative` | FrodoKEM-640 | SLH-DSA |
| 128–255 | `portable` | Dynamic (AES-GCM only) | ML-DSA-87 |

---

## Identity Registry

Nostr was removed. The registry stack is now:

| Backend | Flag | Description |
|---|---|---|
| **WKD** (default) | `--wkd` | HTTPS static file at `https://<domain>/.well-known/maknoon/<user>.json` |
| **DNS** | `--dns` | `_maknoon.<domain>` TXT record (manual setup) |
| **deSEC** | `--desec` | DNS TXT via deSEC.io API (automated) |
| **Local** | `--local` | Add to local contacts only (no network) |

WKD requires an email-style handle (`alice@example.com`). Resolution tries WKD then DNS.

```bash
maknoon identity publish @alice@example.com --wkd    # outputs URL + JSON to upload
maknoon identity publish @alice@example.com --desec  # automated DNS
```

---

## Codebase Map

### Engine Core (`pkg/crypto/`)

| File | Purpose |
|---|---|
| `engine.go` | `Engine` struct, `NewEngine()`, `newShimEngine()` |
| `engine_services.go` | `VaultService`, `IdentityService`, `NetworkService`, `CryptoService` |
| `engine_crypto.go` | Encrypt/decrypt/sign engine wrappers |
| `engine_vault.go` | Vault CRUD, lockout, quorum unlock |
| `engine_identity.go` | Keygen, identity lifecycle |
| `engine_contacts.go` | Contact book (petname → public key) |
| `engine_dispersal.go` | `FragmentFile`, `ReassembleFragments`, `ReassembleToPath` |
| `engine_observability.go` | `Diagnostic`, `AuditExport` |
| `engine_base.go` | `BaseEngine` delegation pattern |
| `audit_engine.go` | `AuditEngine` decorator — logs every operation |
| `audit_loggers.go` | `JSONFileLogger`, `ConsoleAuditLogger`, `VerifyChain()` |
| `interfaces.go` | `MaknoonEngine` interface + `EngineContext` |
| `errors.go` | Typed errors + `FormatMCPError()` |
| `registry.go` | `MultiRegistry`, `IdentityRecord`, resolution cache (5-min TTL) |
| `registry_wkd.go` | WKD registry — HTTPS fetch with SSRF protection |
| `registry_dns.go` | DNS TXT registry + deSEC API publishing |
| `registry_util.go` | `isValidDomain()`, `isPublicIP()` — shared SSRF guard |
| `identity.go` | `IdentityManager`, key save/load/resolve |
| `identity_registry.go` | `IdentityPublish` — WKD + DNS dispatch |
| `contacts.go` | `ContactManager`, `DerivePeerID()` |
| `pipeline.go` | `ProtectStream`, `UnprotectStream` — streaming encrypt/decrypt |
| `asymmetric.go` | ML-KEM / ML-DSA wrappers via CIRCL |
| `storage.go` | `FileSystemKeyStore`, `BboltStore`, `FileSystemVaultStore` |
| `storage_tpm.go` | TPM 2.0 hardware KeyStore (Linux) |
| `policy.go` | `CompositePolicy`, FIPS mode, capability/path/quorum rules |
| `shares.go` | Shamir Secret Sharing |
| `erasure.go` | Reed-Solomon fragment dispersal; V2 header; manifest write/read; `VerifyReassembly()` |
| `profile_dynamic.go` | `DynamicProfile` — runtime custom profiles |
| `config.go` | `Config`, `LoadConfig()`, `Config.Clone()`, `OnConfigChange()` |
| `shred.go` | Secure file deletion (multi-pass overwrite + rename) |

### CLI Commands (`cmd/maknoon/commands/`)

| File | Commands |
|---|---|
| `encrypt.go` / `decrypt.go` | `maknoon encrypt / decrypt` |
| `keygen.go` | `maknoon keygen [--rotate]` |
| `identity.go` | `maknoon identity info/active/delete/rename/publish [--wkd\|--dns\|--desec\|--local]` |
| `contacts.go` | `maknoon contact add/list/remove` |
| `vault.go` / `vault_crud.go` / `vault_shard.go` | `maknoon vault *` (incl. `export` / `import`) |
| `sign.go` / `sign_aggregate.go` / `verify.go` | `maknoon sign/verify` |
| `fragment.go` | `maknoon fragment [--output-manifest]` / `maknoon reassemble [--verify]` |
| `reencrypt.go` | `maknoon reencrypt` — change profile on existing `.makn` file |
| `session.go` | `maknoon session derive` — session key for bulk encryption |
| `audit.go` | `maknoon audit export` / `maknoon audit verify` |
| `config.go` | `maknoon config get/set/validate/export/import/list` |
| `profiles.go` | `maknoon profiles list/gen/rm` |
| `mcp.go` | `maknoon mcp [--transport stdio\|sse]` |
| `serve.go` | `maknoon serve` — MCP SSE + health probes (`/v1/live`, `/v1/ready`, `/v1/health`) |
| `helpers.go` | `InitEngine()`, `LoadPrivateKey()`, presenter utilities |

**Removed commands:** `maknoon registry health` (was Nostr relay ping, removed with Nostr).

### MCP Tools (`cmd/maknoon/commands/mcp_*.go`) — 45 total

All tools have typed argument schemas (`mcp.WithString` / `mcp.WithNumber` / `mcp.WithBoolean`).

| Category | Tools |
|---|---|
| **crypto** | `encrypt_file`†, `decrypt_file`, `sign_file`, `verify_file`, `inspect_file`, `gen_passphrase`, `gen_password`, `reencrypt_file`, `shred_file` |
| **vault** | `vault_get`, `vault_set`, `vault_list`, `vault_delete`, `vault_rename`, `vault_set_blob`, `vault_get_blob`, `vault_split`, `vault_recover`, `vault_init_institutional`, `vault_status`, `vault_check_shards` |
| **identity** | `identity_list`, `identity_keygen`, `identity_info`, `identity_rename`, `identity_delete`, `identity_split`, `identity_combine`, `identity_publish`‡, `contact_list`, `contact_add`, `contact_delete`, `resolve_identity`, `aggregate_signatures` |
| **config** | `config_list`, `config_update`, `config_init`, `diagnostic`, `audit_export`, `audit_verify` |
| **profiles** | `profiles_list`, `profiles_gen`, `profiles_rm` |
| **dispersal** | `fragment_file`§, `reassemble_file`§ |

† `encrypt_file` supports multi-recipient (`public_keys` comma-separated) and directories.  
‡ `identity_publish` registry: `wkd` (default), `dns`, `desec`, `local`.  
§ `fragment_file` has `output_manifest` param; `reassemble_file` has `verify` param.

**MCP error responses** include `"type"` and `"hint"` fields alongside `"error"`:
`authentication_failure` / `security_policy_violation` / `format_error` / `crypto_failure` / `io_error` / `network_error`

---

## Engineering Rules

**Engine pattern:** All business logic lives in `Engine` or its service structs.
CLI and MCP files are controllers only — no crypto, no file I/O, no business logic.

**Presenter pattern:** Return `Result` structs from the engine; render via the
`Presenter` interface. Never call `fmt.Print` or `json.Marshal` in business logic.

**Error handling:** Use the typed error hierarchy in `errors.go`. The MCP layer
calls `FormatMCPError()` which adds structured `type`/`hint` fields for agents.

**MCP helpers (`mcp.go`):**
- `getArgs(req)`, `getString(args, key, def)`, `getInt(args, key, def)`
- `getBool(args, key, def)` — use instead of `args[key].(bool)` assertions
- `getStringSlice(args, key)` — use instead of manual `[]any` loops

**Security:** Always use `SafeClear()` on key material after use. Path containment
checks use `filepath.Rel()` inline so CodeQL tracks the sanitiser. SSRF mitigation
for all network registries is in `registry_util.go` (`isValidDomain` / `isPublicIP`).
Agent-mode path restrictions are enforced in `policy.go`. `AgentPolicy` blocks
`CapVaultDelete`; all other capabilities are permitted.

**Tests:** Unit tests in `pkg/crypto/`; integration tests in `cmd/maknoon/commands/`.
Run with `go test -short ./... -timeout 180s`. Smoke scripts: `scripts/smoke-*.sh`.
Mission tests (Docker): `make missions`.

**Man pages:** 70 per-command man pages in `man/` (generated by `cobra/doc.GenManTree`).
Regenerate with `make man`; hook auto-regenerates on commit if `make install-hooks` was run.
CI verifies content diff — stale pages fail the `Docs` job.

---

## Key Commands

```bash
make build           # statically-linked binary (~12 MB stripped)
make test            # go test -short ./...
make smoke           # audit + resilience + vault-safety + governance smoke scripts
make missions        # Docker-based pipeline + quorum missions
make bench           # crypto benchmarks
make build-matrix    # verify all build tags (linux/darwin/minimal)
make man             # regenerate all 70 man pages into man/
make install-hooks   # install pre-commit hook (auto man page regen)
```

```bash
# MCP
maknoon mcp                                               # stdio (Claude Desktop, Cursor)
maknoon mcp --transport sse --address :8080 \
    --tls-cert cert.pem --tls-key key.pem                # SSE (TLS required)
maknoon call encrypt_file --addr localhost:8080 \
    --args '{"input":"f.pdf","output":"f.pdf.makn"}'     # CLI MCP client

# Identity (WKD is now default — no --nostr)
maknoon keygen -o alice
maknoon identity publish @alice@example.com --wkd        # outputs JSON + URL
maknoon identity publish @alice@example.com --desec      # auto DNS via deSEC.io

# Encrypt for multiple recipients (keys resolved from WKD/DNS)
maknoon encrypt secret.txt -p @alice@corp.com -p @bob@corp.com -o secret.makn

# Vault (new: export / import for migration)
maknoon vault set MY_KEY --vault prod
maknoon vault get MY_KEY --vault prod
maknoon vault export --vault prod -o prod.vault.makn
maknoon vault import --vault restored -i prod.vault.makn

# Audit (new: verify chain integrity)
maknoon audit export
maknoon audit verify

# Session key (bulk encryption — avoids 26ms/file Argon2id cost)
KEY=$(maknoon session derive --passphrase mypass)
maknoon encrypt file.txt --session-key "$KEY"

# Fragment + rclone (RAID-for-Privacy)
maknoon fragment secret.makn --data 5 --parity 3 \
    --output /tmp/shards/ --output-manifest ~/manifest.json
rclone sync /tmp/shards/ s3:bucket/shards/
maknoon shred /tmp/shards/
# recovery:
rclone copy s3:bucket/shards/ /tmp/recover/
cp ~/manifest.json /tmp/recover/manifest.json
maknoon reassemble /tmp/recover/ --output secret.makn --verify
```

---

## Wire Formats

**`.makn` file header:** `MAKN(4) | Ver(1) | ProfileID(1) | Flags(1) | ...`

**Fragment shard (V2):** `MAKF(4) | Ver(1=V1, 2=V2) | Index(1) | Data(1) | Parity(1) | OrigSize(8) | SigSize(2)` = 18 bytes. V1 shards (16 bytes, no SigSize) still reassemble correctly.

**Fragment manifest (`manifest.json`):**
```json
{
  "version": 1, "created_at": "...", "original_name": "...",
  "original_size": 12345, "original_hash": "hex(sha256)",
  "data_shards": 5, "parity_shards": 3, "total_shards": 8,
  "signed": false, "shards": [{"index": 0, "filename": "shard_000.maknf"}, ...]
}
```
`VerifyReassembly(srcDir, outputPath)` checks `original_hash` against the reconstructed file.

**Audit log entry:** `Timestamp(RFC3339) | PrevHash(hex) | Action | Status | Meta(JSON) | Sig(ML-DSA-87)` — hash-chained JSONL; `VerifyChain(path)` in `audit_loggers.go` validates the chain.

**Identity record (`IdentityRecord`):** JSON, ML-DSA-87 signed, `ExpiresAt` enforced (48h TTL). `MultiRegistry.Resolve()` caches valid records for 5 minutes.

**WKD record URL:** `https://<domain>/.well-known/maknoon/<localpart>.json` — same `IdentityRecord` struct. Signature verified on fetch. 64 KB response cap, 10s timeout, SSRF-guarded.
