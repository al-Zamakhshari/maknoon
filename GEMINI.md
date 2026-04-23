# Maknoon (مكنون) - Project Context

Maknoon is a high-performance, post-quantum CLI encryption tool. It focuses on efficiency, security, and future-proofing against quantum computing threats.

## 🏗 Project Architecture (v3.0 - Industrial-Grade)

- **`cmd/maknoon/`**: Entry point (`main.go`). Uses a centralized `Engine` and consumes `EngineEvent` streams for UI decoupling.
- **`pkg/crypto/engine.go`**: The central stateful service. Owns the `SecurityPolicy`, `Config`, and `IdentityManager`. All high-level crypto operations (Protect, Unprotect) are methods of this struct.
- **`pkg/crypto/policy.go`**: Implementation of the **Policy Provider Pattern**. Dictates capability-based security (path validation, resource limits).
- **`pkg/crypto/pipeline.go`**: Implementation of the **Decorator Pattern**. Uses a chain of `Transformer` middleware (Archive, Compress, Encrypt/Decrypt) for processing.
- **`pkg/crypto/errors.go`**: Implementation of **Strong Error Typing**. Define concrete structs for actionable error handling.
- **`integrations/mcp/`**: MCP Server for AI Agent interaction. Fully integrated with the Agent Sandbox and uses typed errors for structured responses.

## 🛡 Cryptographic Stack

- **Symmetric Cipher**: XChaCha20-Poly1305 (AEAD) with 192-bit nonces.
- **Asymmetric Encryption (KEM)**: ML-KEM / Kyber1024 (NIST Standard) wrapped in standard **HPKE Seal/Open** (RFC 9180).
- **Digital Signatures**: ML-DSA-87 / Dilithium (NIST Standard).
- **Key Derivation (KDF)**: Argon2id (Time: 3, Memory: 64MB).
- **Secret Sharing**: Shamir's SSS over $GF(2^8)$ with BIP-39 style mnemonics.

## 🤖 Agent Sandbox & "Restricted Mode"

Maknoon implements a strict **Capability-Based Sandbox** for autonomous environments (triggered via `MAKNOON_AGENT_MODE=1` or `--json`):

1.  **Filesystem Isolation**: Restricted to the user's Home directory (`~/`) and system Temp directories.
2.  **Resource Governance**: Parallel workers are clamped (default: 2), and Argon2id parameters are capped to prevent DoS.
3.  **Network Boundaries**: P2P transfers are restricted to a configurable allow-list of trusted Rendezvous/Transit servers.
4.  **Immutable Config**: Agents are physically blocked from using `config set` or `config init` to modify global security policies.
5.  **Ephemeral Profiles**: Agents can generate profiles as JSON output but cannot persist them to disk.

## 📋 Engineering Standards & Design Patterns

### 1. The Engine Pattern
All business logic must be invoked via the `Engine` struct. Do not call low-level crypto functions directly from CLI commands.
- **`engine.Protect`**: Orchestrates "Archive -> Compress -> Encrypt" using a `Transformer` chain.
- **`engine.Unprotect`**: Orchestrates "Decrypt -> Decompress -> Extract" using a `Transformer` chain.

### 2. The Decorator Pattern (Middleware)
Processing pipelines MUST be implemented as interchangeable `Transformer` middleware. This ensures logical isolation between archiving, compression, and encryption.

### 3. The Observer Pattern (Telemetry)
The `Engine` must not have any UI dependencies. Use the `EventStream` (`chan<- EngineEvent`) to emit telemetry for progress bars, logging, or monitoring.

### 4. Strong Error Typing
Avoid generic errors. All new failure modes must be defined as typed structs in `pkg/crypto/errors.go` and wrapped using `%w`. This allows programmatic consumers (like the MCP server) to handle failures reliably.

### 5. Registry Factory (Extensibility)
Identity Discovery is pluggable. New registry types (e.g., LDAP, Keybase) should be implemented as an `IdentityRegistry` and registered via `RegisterRegistry` in an `init()` function.

### 6. Pluggable Audit Decorator
Enterprise logging is implemented via the Decorator and Strategy patterns. The `AuditEngine` wraps the core `Engine` to intercept operations and delegate structured logging to pluggable sinks (`JSONFileLogger`, `NoopLogger`). This ensures zero bloat in the cryptographic core and zero overhead for stealth users.

### 7. Policy Provider Pattern
Avoid "Mode-Based" logic (if IsAgentMode). Instead, query the engine.Policy object for permissions (e.g., engine.Policy.ValidatePath(path)).

### 8. Centralized Security Validation
All file system operations MUST be validated using the engine's policy. The sandbox is enforced at the entry point of the `Engine` methods.

### 8. Memory Hygiene
Use `crypto.SafeClear` (aliased to `memguard.WipeBytes`) immediately after sensitive data use. Deterministic wiping is mandatory for FEKs and private keys.

## 🛠 Building and Running

### Key Commands
- **Build**: `go build -o maknoon ./cmd/maknoon`
- **Test (Quick)**: `go test -v -short ./...` (Skips flaky network tests)
- **Schema**: `maknoon schema` (Generates JSON metadata for agents)

## 🧪 Current Status
- **Architecture**: V3 (Industrial-Grade) completed.
- **Design Patterns**: Fully implemented (Engine, Policy, Decorator, Observer, Factory, Strong Typing).
- **Agent Sandbox**: Fully Sealed (v1.5 Security Audit verified).
- **Build Integrity**: Pre-flight checks (gofmt, vet, staticcheck, agent-schema) enforced on commit.
