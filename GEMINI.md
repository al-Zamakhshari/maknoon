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
- **Asymmetric Encryption (KEM)**: ML-KEM / Kyber1024 (NIST Standard) wrapped in standard **HPKE Seal/Open** (RFC 9180).
- **Digital Signatures**: ML-DSA-87 / Dilithium (NIST Standard) for forensic integrity; **ECDSA-P384** for ephemeral transport certificates. RSA-2048 has been completely purged.
- **KMS Envelope Encryption**: Enterprise-grade `Wrap`/`Unwrap` primitives using hybrid ML-KEM-768 to secure massive data sets via encapsulated 32-byte Data Encryption Keys (DEKs).
- **Key Derivation (KDF)**: Argon2id (Industrial Standard: 3 iterations, 64MB memory).
- **Transport Security**: Mandated TLS 1.3 with native X25519MLKEM768 hybrid key exchange for all networked interfaces.

## 🚀 P2P & Identity Lessons

- **Identity Collision**: Never use `libp2p.FallbackDefaults` when providing a custom identity. This triggers a "cannot specify multiple identities" error.
- **Explicit Identity**: All P2P operations (`send`, `receive`, `chat`) support explicit identity selection via the `--identity` flag.
- **Transport Agnosticism**: The Maknoon P2P Wire Protocol (defined in `p2p_message.go`) is isolated from the `libp2p` transport.
- **MCP-over-SSE**: Tool responses are pushed through the long-lived SSE stream (`/sse`), not the POST body.
- **Identity Discovery Service**: The REST API now exposes decentralized **Nostr/DNS resolution** as a service, allowing external apps to discover PQC public keys via a simple GET request.

## 🏗 Mission & Docker Infrastructure Lessons

- **ENTRYPOINT vs. COMMAND Conflict**: When using `ENTRYPOINT ["maknoon"]` in a Dockerfile, Docker Compose `command: ["sh", "-c", "..."]` passes `sh` as an argument to `maknoon`, leading to errors. For mission-ready images, use a bare image and define the full execution logic in the Compose file or use a shell-based `ENTRYPOINT`.
- **Volume Permission Shadowing**: Mounted volumes often default to root ownership. Use the `su-exec` pattern: start as `root`, `chown` the mount point, and then drop privileges using `su-exec maknoon ...`.
- **Mandated TLS In Containers**: When running `mcp --transport sse` or `serve` in Docker, TLS is no longer optional. Use shared volumes (e.g., `./certs:/certs:ro`) to provide certificates to all nodes in the DMZ.
- **Shell Quoting in YAML**: Avoid double-quoting shell command blocks in YAML (e.g., `command: "sh -c '...'"`). Use the literal block scalar `>` or a simple string to prevent argument misparsing.
-   **Verification Robustness**: Integration scripts MUST implement explicit timeouts and log capturing for failing services to prevent infinite "wait" loops in CI.
-   **Test Environmental Isolation**: Unit tests that interact with the filesystem (Vaults, Config) MUST override the `HOME` environment variable and call `commands.ResetGlobalConfig()` to ensure a clean state and prevent contamination from the developer's real environment.

## 🏆 Industrial Mission Lessons (Red-Team Verification)

- **Nested Verification (Blind Proxy)**: The engine supports verifying outer PQC signatures while remaining "blind" to inner payloads. This allows secure relay orchestration without exposing end-to-end private keys at the transport layer.
- **P2P Network Bridging**: DHT-based discovery is resilient across disconnected network segments when a bootstrap node is reachable via a secure P2P relay. SOCKS5 gateways over PQC L4 tunnels provide industrial-grade cross-network security.
- **Master Secret Sharding (Dead Man's Switch)**: Secret sharding (SSS) for the master passphrase is the definitive protection against single-point-of-failure in automated vaults. 3-of-4 thresholds provide the ideal balance of availability and security.
- **Memory-Safe KMS Primitive**: 
    - **Buffer Ownership**: `memguard.NewEnclave(buf)` takes ownership of the source buffer and **wipes it immediately**. When returning a plaintext DEK, you MUST copy it to a new slice *before* creating the enclave.
    - **Locked Buffer Lifecycle**: Bytes opened from an enclave (`lb.Bytes()`) must be copied to a new buffer if they need to persist after `lb.Destroy()` is called.
- **Dynamic Configuration Agility**:
    - **Policy Precedence**: In `AgentMode`, the `SecurityPolicy` must explicitly allow `CapConfig` for runtime management. 
    - **CLI Flag Shadowing**: Hardcoded CLI flag defaults (e.g., `encrypt --profile nist`) can shadow dynamic engine configuration updates. For live-migration to work, CLI flags should default to empty/zero to allow the `Engine`'s internal `DefaultProfile` to take priority.
    - **Runtime Propagation**: MCP-initiated configuration changes (`config_update`) are persistent across process boundaries because the engine explicitly calls `Save()` on the config object, but active long-running loops require a re-initialization or configuration polling mechanism to pick up changes without a restart.

## 🤖 Agent Sandbox & Composable Governance

1.  **Composite Governance**: The engine implements a `CompositePolicy` (Strictest-Wins) allowing multiple active layers (e.g., Global FIPS + Local Project Rules).
2.  **Declarative Policies**: Support for loading human-readable JSON governance files via `--policy`. These files define `allow`/`deny` rules for capabilities, regex-based paths, and URL endpoints.
3.  **FIPS Compliance Mode**: The `--fips` flag enforces mandatory NIST `nist` profiles, prohibits unverified TLS tunnels, and freezes system configuration.
4.  **Forensic Integrity**: 
    *   All operations are logged via the `AuditEngine` decorator.
    *   Logs are cryptographically signed using **ML-DSA-87**.
    *   Support for **Hardware-Backed Forensic Signing** (binding audit integrity to physical FIDO2 keys).

## 🏆 Industrial Mission Lessons (Red-Team Verification)

- **Cryptographic Purge**: RSA and XChaCha20 were removed to eliminate "legacy surface." Industrial compliance mandates AES-GCM and ECDSA-P384 for ephemeral operations.
- **Resilience Engineering**: 
    *   **Zero-Downtime Reloading**: Global servers support `SIGHUP` for non-disruptive TLS certificate rotation.
    *   **Rate Limiting**: Mandatory global rate limiting (Token Bucket) prevents API saturation.
- **Power-On Self-Test (POST)**: Every engine startup triggers a Known-Answer Test (KAT) for all core algorithms (ML-KEM, ML-DSA, AES-GCM). Failure results in a fatal halt.
- **Secure Memory Scoping**: Integration of `memguard` across CLI and Engine boundaries ensures sensitive material (DEKs, Passphrases) is wiped on exit, crash, or interrupt.

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

## 🧪 Current Status
- **Architecture**: V1.4.x (Hardened Governance Engine & Industrial Purge complete).
- **Parity**: 1:1 mapping between CLI commands, MCP tools, and REST endpoints with high-fidelity results.
- **Testing**: Passed all 90+ unit, integration, and fuzz tests; verified full industrial smoke suite.
- **Coverage**: **~55%** statement coverage in `pkg/crypto`.
- **Security**: FIPS-compliant AES-256-GCM, ECDSA-P384, and ML-KEM/DSA stack verified.
