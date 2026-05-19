# Maknoon — Agent Instructions

Maknoon is a post-quantum cryptographic engine and MCP gateway. A single
statically-linked binary (~20 MB) hosts the CLI and the native MCP server.

---

## Current Architecture

| Layer | Description |
|---|---|
| **CLI** | Cobra commands in `cmd/maknoon/commands/` |
| **MCP server** | ~31 tools over stdio or SSE; registered in `mcp_*.go` |
| **Engine** | `pkg/crypto/Engine` — all business logic; CLI/MCP are thin controllers |
| **Vault** | bbolt-backed encrypted KV store; Argon2id key derivation |
| **Identity registry** | Nostr (primary, concurrent relay fan-out) → DNS TXT records |
| **Crypto kernel** | ML-KEM-768 + X25519 hybrid KEM; ML-DSA-87 signatures; AES-256-GCM |

**What was removed (do not reference these):**
P2P tunnel, libp2p DHT, BEP-44, FIDO2, Badger backend, OTEL, WorkspaceService,
AES-GCM-SIV, REST API handlers (only health/live/ready probes remain in `serve.go`).

---

## Cryptographic Stack

- **Symmetric:** AES-256-GCM (AEAD) — only cipher in use
- **KEM:** ML-KEM-768 + X25519 (X-Wing, Profile 1 / NIST). Conservative option: FrodoKEM-640 (Profile 3)
- **Signatures:** ML-DSA-87 (primary); SLH-DSA-SHA2-128f (Profile 3 conservative)
- **KDF:** Argon2id (3 iterations, 64 MB memory, 4 threads by default)
- **Transport:** TLS 1.3 with X25519MLKEM768 hybrid for SSE mode
- **Key fingerprint:** `"mk" + hex(sha256(sigPub)[:8])` — stored as `peer_id` in contacts (libp2p removed)

**Profiles:**
| ID | Name | KEM | SIG |
|---|---|---|---|
| 1 | `nist` | ML-KEM-768 + X25519 | ML-DSA-87 |
| 3 | `conservative` | FrodoKEM-640 | SLH-DSA |
| 128–255 | `portable` | Dynamic (AES-GCM only) | ML-DSA-87 |

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
| `engine_dispersal.go` | Fragment reassembly wrapper |
| `engine_observability.go` | `NetworkStatus`, `Diagnostic`, `AuditExport` |
| `engine_base.go` | `BaseEngine` delegation pattern |
| `audit_engine.go` | `AuditEngine` decorator (logs all operations) |
| `audit_loggers.go` | `JSONFileLogger`, `ConsoleAuditLogger`, `NoopLogger` |
| `interfaces.go` | `MaknoonEngine` interface + `EngineContext` |
| `errors.go` | Typed errors (`ErrAuthentication`, `ErrCrypto`, etc.) + `FormatMCPError()` |
| `registry.go` | `MultiRegistry`, `IdentityRecord`, resolution cache (5-min TTL) |
| `registry_nostr.go` | Nostr relay registry (concurrent fan-out, `HealthCheck`) |
| `registry_dns.go` | DNS TXT registry + deSEC API publishing |
| `identity.go` | `IdentityManager`, key save/load/resolve |
| `identity_registry.go` | `IdentityPublish` — Nostr + DNS paths |
| `contacts.go` | `ContactManager`, `DerivePeerID()` (sha256 fingerprint) |
| `encrypt.go` / `decrypt.go` | AES-GCM streaming pipeline, session-keyed variants |
| `pipeline.go` | `ProtectStream`, `UnprotectStream` — top-level encrypt/decrypt |
| `asymmetric.go` | ML-KEM / ML-DSA wrappers via CIRCL |
| `storage.go` | `FileSystemKeyStore`, `BboltStore`, `FileSystemVaultStore` |
| `storage_tpm.go` | TPM 2.0 hardware KeyStore (Linux) |
| `policy.go` | `CompositePolicy`, FIPS mode, capability/path/quorum rules |
| `shares.go` | Shamir Secret Sharing |
| `erasure.go` | Reed-Solomon fragment dispersal [EXPERIMENTAL] |
| `profile_dynamic.go` | `DynamicProfile` — runtime custom profiles |
| `quorum.go` | `QuorumAction`, `QuorumResponse`, `GenerateTraceID()` |
| `config.go` | `Config`, `LoadConfig()`, `Config.Clone()`, `OnConfigChange()` |
| `shred.go` | Secure file deletion |

### CLI Commands (`cmd/maknoon/commands/`)

| File | Commands |
|---|---|
| `encrypt.go` / `decrypt.go` | `maknoon encrypt / decrypt` |
| `keygen.go` | `maknoon keygen [--rotate]` |
| `identity.go` | `maknoon identity info/active/delete/rename/publish` |
| `vault.go` / `vault_crud.go` / `vault_shard.go` | `maknoon vault *` |
| `sign.go` / `sign_aggregate.go` / `verify.go` | `maknoon sign/verify` |
| `fragment.go` | `maknoon fragment/reassemble` [EXPERIMENTAL] |
| `reencrypt.go` | `maknoon reencrypt` — change profile on existing `.makn` file |
| `contacts.go` | `maknoon contact add/list/delete` |
| `session.go` | `maknoon session derive` — session key for bulk encryption |
| `registry.go` | `maknoon registry health` — Nostr relay connectivity |
| `config.go` | `maknoon config get/set/validate/export/import/list` |
| `mcp.go` | `maknoon mcp [--transport stdio|sse]` |
| `serve.go` | `maknoon serve` — health probes only (/v1/live, /v1/ready, /v1/health) |
| `audit.go` | `maknoon audit export/view` |
| `helpers.go` | `InitEngine()`, `LoadPrivateKey()`, presenter utilities |

### MCP Tools (`cmd/maknoon/commands/mcp_*.go`)

| Category | Tools |
|---|---|
| **crypto** | `encrypt_file`, `decrypt_file`, `sign_file`, `verify_file`, `inspect_file`, `gen_passphrase`, `gen_password`, `reencrypt_file` |
| **identity** | `identity_list`, `identity_keygen`, `identity_info`, `identity_rename`, `identity_delete`, `identity_split`, `identity_combine`, `identity_publish`, `contact_list`, `contact_add`, `contact_delete`, `resolve_identity`, `aggregate_signatures` |
| **vault** | `vault_get`, `vault_set`, `vault_list`, `vault_delete`, `vault_rename`, `vault_set_blob`, `vault_get_blob`, `vault_split`, `vault_recover`, `vault_init_institutional` |
| **config** | `config_get`, `config_set`, `profiles_list`, `profiles_gen` |

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

**Tests:** Unit tests in `pkg/crypto/`; integration tests in `cmd/maknoon/commands/`.
Run with `go test -short ./... -timeout 180s`. Smoke scripts: `scripts/smoke-*.sh`.
Mission tests (Docker): `make missions` — runs `mission-pipeline-verify` and
`mission-quorum-verify`.

**Security:** Always use `SafeClear()` on key material after use. Path containment
checks use `filepath.Rel()` inline (not in a helper) so CodeQL tracks the sanitiser.
Agent-mode path restrictions are enforced in `policy.go` and `shred.go`.

---

## Key Commands

```bash
make build          # statically-linked binary
make test           # go test -short ./...
make smoke          # audit + resilience + vault-safety + governance smoke scripts
make missions       # Docker-based pipeline + quorum missions
make bench          # crypto benchmarks
make build-matrix   # verify all build tags (linux/darwin/minimal)
```

```bash
# MCP
maknoon mcp                                              # stdio (Claude Desktop, Cursor)
maknoon mcp --transport sse --address :8080 \
    --tls-cert cert.pem --tls-key key.pem               # SSE (TLS required)

# Identity
maknoon keygen -o alice
maknoon identity publish @alice --nostr
maknoon registry health --json

# Encrypt for multiple recipients (keys resolved from Nostr/DNS)
maknoon encrypt secret.txt -p @alice -p @bob -o secret.makn

# Vault
maknoon vault set MY_KEY --vault prod --passphrase pass
maknoon vault get MY_KEY --vault prod --passphrase pass

# Session key (bulk small-file encryption — avoids 26ms/file Argon2id cost)
KEY=$(maknoon session derive --passphrase mypass)
maknoon encrypt file.txt --session-key "$KEY"
```

---

## Wire Formats

**`.makn` file header:** `MAKN(4) | Ver(1) | ProfileID(1) | Flags(1) | ...`

**Fragment shard:** `MAKF(4) | Ver(1) | Index(1) | Data(1) | Parity(1) | ShardSize(8) | ShardData(N) | Sig(ML-DSA)`

**Audit log entry:** `Timestamp(RFC3339) | PrevHash(hex) | Action | Status | Meta(JSON) | Sig(ML-DSA-87)`

**Identity record** (`IdentityRecord`): JSON, ML-DSA-87 signed, `ExpiresAt` enforced (48h default TTL). `MultiRegistry.Resolve()` caches valid records for 5 minutes.
