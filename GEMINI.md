# Maknoon (مكنون) - Project Context

Maknoon is an industrial-grade, post-quantum CLI encryption engine and Model Context Protocol (MCP) server. It focuses on functional density, cryptographic integrity, and secure AI agent orchestration.

## 🏗 Project Architecture (v1.x Series - Industrial PQC Backbone)

- **`Unified Binary`**: A single statically linked binary hosts the CLI, the native MCP server, and the new **Service-Grade REST API**. Mode of operation is determined by the command: `keygen`, `mcp`, or `serve`.
- **`Pure Engine (DI)`**: The central Engine is fully decoupled from the environment via **Dependency Injection**. It follows a **Modular SRP Structure** where the monolithic core is split into specialized logic files (`engine_crypto.go`, `engine_vault.go`, `engine_p2p.go`, etc.) to improve context efficiency and maintainability.
- **`Modular CLI Commands`**: CLI command logic is decomposed into scoped files (e.g., `vault.go`, `vault_crud.go`, `vault_shard.go`) to prevent file bloating and facilitate targeted feature updates.
- **`Domain-Specific Test Suites`**: Integration tests are organized into domain-specific suites (`commands_crypto_test.go`, `commands_vault_test.go`) for faster execution and clearer failure attribution.
- **`Service-Grade Storage`**: In addition to standard `bbolt`, we now support **BadgerDB v4** as a high-concurrency, server-optimized LSM-tree backend for high-volume API workloads.
- **`Presenter Pattern`**: All user-facing output is managed via the `Presenter` interface. Logic layer returns structured `Result` objects; UI layer renders them as pretty tables (CLI) or JSON (MCP/Agent/REST).
- **`Transformer Pipeline`**: Data streaming is organized into a modular pipeline defined in `pkg/crypto/transformer.go`. Pluggable stages (Compressor, Encryptor, Archiver) can be chained dynamically.
- **`Dual-Transport MCP & REST`**: Supports local `stdio`, remote `sse` (MCP), and a full **enterprise REST API**. Remote sessions are strictly secured via **Post-Quantum TLS 1.3** (prioritizing ML-KEM).
- **`Container Sandbox`**: Multi-stage `scratch` build (~13MB) with zero OS attack surface. Runs as a non-privileged user (`1000:1000`).

## 🛡 Cryptographic Stack

- **Symmetric Cipher**: AES-256-GCM (AEAD) / AES-256-GCM-SIV. XChaCha20-Poly1305 has been purged to ensure 100% industrial compliance.
- **Asymmetric Encryption (KEM)**: ML-KEM / Kyber1024 (NIST Standard) wrapped in standard **HPKE Seal/Open** (RFC 9180). Supports **Non-Lattice Hedging** via Profile 3 (FrodoKEM-640 + SLH-DSA).
- **Digital Signatures**: ML-DSA-87 / Dilithium (NIST Standard) for forensic integrity; **ECDSA-P384** for ephemeral transport certificates. Support for **SLH-DSA** in conservative modes. RSA-2048 has been completely purged.
- **KMS Envelope Encryption**: Enterprise-grade `Wrap`/`Unwrap` primitives using hybrid ML-KEM-768 to secure massive data sets via encapsulated 32-byte Data Encryption Keys (DEKs).
- **Key Derivation (KDF)**: Argon2id (Industrial Standard: 3 iterations, 64MB memory).
- **Transport Security**: Mandated TLS 1.3 with native X25519MLKEM768 hybrid key exchange for all networked interfaces.

## 🚀 P2P & Identity Lessons

- **Identity Format**: Maknoon Identities are **Hybrid ML-DSA-87 + Ed25519** bundles. Ed25519 is used for the libp2p PeerID, while ML-DSA-87 is used for forensic payload signing.
- **Identity Collision**: Never use `libp2p.FallbackDefaults` when providing a custom identity. This triggers a "cannot specify multiple identities" error.
- **Explicit Identity**: All P2P operations (`send`, `receive`, `chat`, `tunnel`) support explicit identity selection via the `--identity` flag.
- **Transport Agnosticism**: The Maknoon P2P Wire Protocol (defined in `p2p_message.go`) is isolated from the `libp2p` transport.
- **MCP-over-SSE**: Tool responses are pushed through the long-lived SSE stream (`/sse`), not the POST body. Requires explicit certificate loading (`SetActiveCertificate`) to avoid internal handshake errors.
- **Identity Discovery Service**: The REST API now exposes decentralized **Nostr/DNS resolution** as a service, allowing external apps to discover PQC public keys via a simple GET request.

## 🏗 Mission & Docker Infrastructure Lessons

- **ENTRYPOINT vs. COMMAND Conflict**: When using `ENTRYPOINT ["maknoon"]` in a Dockerfile, Docker Compose `command: ["sh", "-c", "..."]` passes `sh` as an argument to `maknoon`, leading to errors. For mission-ready images, use a bare image and define the full execution logic in the Compose file or use a shell-based `ENTRYPOINT`.
- **Volume Permission Shadowing**: Mounted volumes often default to root ownership. Use the `su-exec` pattern: start as `root`, `chown` the mount point, and then drop privileges using `su-exec maknoon ...`.
- **Mandated TLS In Containers**: When running `mcp --transport sse` or `serve` in Docker, TLS is no longer optional. Use shared volumes (e.g., `./certs:/certs:ro`) to provide certificates to all nodes in the DMZ.
- **Shell Quoting in YAML**: Avoid double-quoting shell command blocks in YAML (e.g., `command: "sh -c '...'"`). Use the literal block scalar `>` or a simple string to prevent argument misparsing.
- **Verification Robustness**: Integration scripts MUST implement explicit timeouts and log capturing for failing services to prevent infinite "wait" loops in CI.
- **Test Environmental Isolation**: Unit tests that interact with the filesystem (Vaults, Config) MUST override the `HOME` environment variable and call `commands.ResetGlobalConfig()` to ensure a clean state and prevent contamination from the developer's real environment.
- **Go Module Cache Noise**: Isolated tests with `HOME` redirection must recursively grant write permissions (`chmod -R +w`) before cleaning up `TEST_DIR` to avoid "Permission denied" errors on read-only module paths.

## 🏆 Industrial Mission Lessons (Red-Team Verification)

- **Nested Verification (Blind Proxy)**: The engine supports verifying outer PQC signatures while remaining "blind" to inner payloads. This allows secure relay orchestration without exposing end-to-end private keys at the transport layer.
- **P2P Network Bridging**: DHT-based discovery is resilient across disconnected network segments when a bootstrap node is reachable via a secure P2P relay. SOCKS5 gateways over PQC L4 tunnels provide industrial-grade cross-network security.
- **RAID-for-Networking (Phase 7.4)**: L4 Tunnels support stream-level **Reed-Solomon erasure coding**. Data is striped across multiple parallel sessions (lanes), surviving up to 66% lane failure with zero connection drop. Parameters: `--data-lanes` and `--parity-lanes`.
- **Master Secret Sharding (Dead Man's Switch)**: Secret sharding (SSS) for the master passphrase is the definitive protection against single-point-of-failure in automated vaults. 3-of-4 thresholds provide the ideal balance of availability and security.
- **MPC Pivot (Phase 6.2)**: Standard MPC protocols like FROST are mathematically incompatible with lattice-based ML-DSA (rejection sampling). Maknoon favors **Orchestrated Quorum Unlocking**: a high-fidelity combination of Phase 6.1 (Threshold-Sig) and Phase 7.4 (Resilient Tunnels) to securely reconstruct vault DEKs inside `memguard` enclaves only after quorum consensus.
- **Memory-Safe KMS Primitive**: 
    - **Buffer Ownership**: `memguard.NewEnclave(buf)` takes ownership of the source buffer and **wipes it immediately**. When returning a plaintext DEK, you MUST copy it to a new slice *before* creating the enclave.
    - **Locked Buffer Lifecycle**: Bytes opened from an enclave (`lb.Bytes()`) must be copied to a new buffer if they need to persist after `lb.Destroy()` is called.

## 🤖 Agent Sandbox & Composable Governance

1.  **Composite Governance**: The engine implements a `CompositePolicy` (Strictest-Wins) allowing multiple active layers (e.g., Global FIPS + Local Project Rules).
2.  **Declarative Policies**: Support for loading human-readable JSON governance files via `--policy`. These files define `allow`/`deny` rules for capabilities, regex-based paths, URL endpoints, and **Threshold-bound rules (Phase 6.3)** for administrative quorum.
3.  **FIPS Compliance Mode**: The `--fips` flag enforces mandatory NIST `nist` profiles, prohibits unverified TLS tunnels, and **strictly freezes system configuration** (rendering it entirely immutable at runtime).
4.  **Forensic Integrity**: 
    *   All operations are logged via the `AuditEngine` decorator.
    *   **Chained Auditing**: Logs are cryptographically linked using SHA-256 hashes (each entry points to the `prev_hash`), ensuring the entire trail is immutable and tamper-evident.
    *   Logs are cryptographically signed using **ML-DSA-87**.
    *   **Entropy Sentinel**: Implements **CRNGT** (Continuous Random Number Generator Test) to detect hardware entropy failures at runtime, preventing insecure key generation.
    *   Support for **Hardware-Backed Forensic Signing** (binding audit integrity to physical FIDO2 keys).

## 📋 Engineering & Documentation Standards

### 1. The Skeptical Engineering Persona
- **Empirical Rigor**: Never assume a feature works just because it compiles or passed a shallow test. Demand high-fidelity E2E verification for all critical paths.
- **Dependency Suspicion**: Treat all third-party libraries (even core ones like libp2p) as potential sources of bloat, complexity, and failure.
- **Proof of Failure**: Before applying a fix, you MUST empirically reproduce the failure. Use the `make smoke` suite for industrial verification.

### 2. The Engine Pattern
All business logic must be invoked via the `Engine` struct. UI layers (CLI/MCP/REST) must remain strictly as controllers. **Mandatory DI**: New services must accept their dependencies in the constructor. The `SecurityPolicy` interface acts as the definitive boundary for engine capabilities.

### 3. UI-Agnostic Design (Presenter)
NEVER use `fmt.Print` or `json.Marshal` directly in business logic. Use the `Presenter` interface to maintain consistency across CLI, Agent, and REST modes.

### 4. Testing Mandates
- **Universal Missions**: All integration tools must be verified by a transport-agnostic mission suite.
- **Industrial Smoke Suite**: Every release must pass `make smoke` (Audit, Resilience, Vault Safety, and Governance sub-suites).
- **Integrity**: Every new feature requires a functional smoke test, a policy-violation test, and an enterprise unit test suite.

## 🛠 Building and Running

### Key Commands (Makefile)
- **Build**: `make build` (Produces optimized statically linked binary)
- **Test**: `make test` (Runs industry-standard unit suite)
- **Smoke**: `make smoke` (Executes the full industrial hardening verification suite)
- **Docker**: `make docker-build` (Generates OCI-compliant secure sandbox)

## 🗺 Codebase Architectural Map

### 🧠 The Engine Core (`pkg/crypto/`)
- **`engine.go`**: Core initialization and capability enforcement.
- **`engine_crypto.go`**: High-level encryption/decryption/signing orchestration.
- **`engine_vault.go`**: Vault lifecycle, CRUD, and passphrase management.
- **`engine_p2p.go`**: P2P protocol coordination (libp2p lifecycle).
- **`engine_identity.go`**: ML-DSA/Ed25519 identity generation and registry ops.
- **`engine_observability.go`**: Audit logging and telemetry hooks.
- **`engine_dispersal.go`**: (Phase 7) Fragment dispersal and RAID-for-Privacy logic.

### 🛡 Cryptographic Primitives (`pkg/crypto/`)
- **`encrypt.go` / `decrypt.go`**: AEAD (AES-GCM) and HPKE (ML-KEM) streaming.
- **`asymmetric.go`**: ML-KEM/ML-DSA standard wrappers (using CIRCL).
- **`entropy.go`**: (Phase 8) Entropy Sentinel and FIPS CRNGT implementation.
- **`integrity.go`**: Power-On Self-Tests (POST) and algorithm verification.
- **`storage.go`**: KeyStore and VaultStore abstractions.
- **`storage_tpm.go`**: (Phase 8) TPM 2.0 hardware-backed KeyStore.
- **`shares.go`**: Shamir's Secret Sharing (SSS) implementation.
- **`fido2.go`**: Hardware-backed signing via FIDO2/WebAuthn.
- **`policy.go`**: The Governance Engine (Human vs. Agent constraints).

### 📡 Networking & Resilience
- **`pkg/tunnel/resilient.go`**: (Phase 7.4) Reed-Solomon lane striping for tunnels.
- **`pkg/crypto/p2p_message.go`**: Wire protocol definitions.
- **`pkg/crypto/p2p_send.go`**: Direct P2P transfer logic.
- **`pkg/crypto/p2p_fragment.go`**: Pull-based shard retrieval.

### 🎮 Orchestration & UI (`cmd/maknoon/commands/`)
- **`mcp.go`**: Main MCP server logic.
- **`serve.go`**: Enterprise REST API server.
- **`call.go`**: Native MCP SSE client for testing.

## 🏁 Phase Roadmap (v1.x)
1. [DONE] **Phase 1-3**: Core CLI, PQC Engine, and Vault CRUD.
2. [DONE] **Phase 4**: P2P Networking (libp2p) and Direct Shard Transfer.
3. [DONE] **Phase 5**: Model Context Protocol (MCP) and REST API parity.
4. [DONE] **Phase 6.1**: PQC Threshold Multi-Sig (M-of-N signing).
5. [DONE] **Phase 6.2**: Orchestrated Quorum Unlocking (Consensus-based vaults).
6. [DONE] **Phase 7**: RAID-for-Privacy (Reed-Solomon dispersal & retrieval).
7. [DONE] **Phase 7.4**: Resilient L4 Tunnels (Reed-Solomon lane striping).
8. [IN PROGRESS] **Phase 8**: Post-Quantum FIPS Certification & Final Hardening.
    - **Entropy Sentinel (CRNGT)**: Real-time entropy health monitoring (FIPS 140-3). [DONE]
    - **Expanded POST**: ML-KEM, ML-DSA, and Argon2id Known Answer Tests on startup. [DONE]
    - **Chained Forensic Auditing**: Immutable, hash-linked audit trails. [DONE]
    - **TPM 2.0 Hardening**: Hardware-backed identity protection for Linux (Pure Go). [DONE]

## ⚙️ Protocol & Header Specifications

### 📦 Dispersal Fragment Format (MAKF)
`[MAKF(4), Ver(1), Index(1), Data(1), Parity(1), ShardSize(8), ShardData(N), ForensicSig(ML-DSA)]`

### 🔑 Forensic Audit Log Format
`[Timestamp(RFC3339), PrevHash(Hex), Action(string), Status(string), Meta(JSON), Signature(ML-DSA-87)]`

## ⚡ Rapid Reference (Agent Cheat Sheet)

### MCP Server Entry Points:
- **Stdio**: `maknoon mcp`
- **SSE**: `maknoon mcp --transport sse --address :8080 --tls-cert cert.pem --tls-key key.pem`
- **Verification**: `./maknoon call profiles_list --addr 127.0.0.1:8080 --insecure`

### Core MCP Tools:
- **Vault**: `vault_get`, `vault_set`, `vault_list`, `vault_shard_check`
- **Network**: `tunnel_start`, `tunnel_stop`, `p2p_identity_get`, `p2p_send`, `fragment_retrieve`
- **Crypto**: `encrypt_file`, `decrypt_file`, `sign_aggregate`, `verify_threshold`
- **Config**: `profiles_list`, `profiles_gen`, `config_update`
