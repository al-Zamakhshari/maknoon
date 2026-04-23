# Maknoon (مكنون) - Project Context

Maknoon is a high-performance, post-quantum CLI encryption tool. It focuses on efficiency, security, and future-proofing against quantum computing threats.

## 🏗 Project Architecture (v2.0 - Policy Driven)

- **`cmd/maknoon/`**: Entry point (`main.go`). Now uses a centralized `Engine` instantiated with either a `HumanPolicy` or `AgentPolicy` at startup.
- **`pkg/crypto/engine.go`**: The central stateful service. Owns the `SecurityPolicy`, `Config`, and `IdentityManager`. All high-level crypto operations (Protect, Unprotect) are methods of this struct.
- **`pkg/crypto/policy.go`**: Implementation of the **Policy Provider Pattern**. Dictates capability-based security (path validation, resource limits).
- **`pkg/crypto/`**: Core library implementing the cryptographic pipeline, streaming logic, and FIDO2 integration.
- **`integrations/mcp/`**: MCP Server for AI Agent interaction. Now fully integrated with the Agent Sandbox.

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
- **`engine.Protect`**: Orchestrates "Archive -> Compress -> Encrypt" under active policy.
- **`engine.Unprotect`**: Orchestrates "Decrypt -> Decompress -> Extract" under active policy.

### 2. Policy Provider Pattern
Avoid "Mode-Based" logic (`if IsAgentMode`). Instead, query the `engine.Policy` object for permissions (e.g., `engine.Policy.ValidatePath(path)`).

### 3. Centralized Security Validation
All file system operations MUST be validated using the engine's policy. The sandbox is enforced at the entry point of the `Engine` methods.

### 4. Memory Hygiene
Use `crypto.SafeClear` (aliased to `memguard.WipeBytes`) immediately after sensitive data use.
deterministic wiping is mandatory for FEKs and private keys.

## 🛠 Building and Running

### Key Commands
- **Build**: `go build -o maknoon ./cmd/maknoon`
- **Test (Quick)**: `go test -v -short ./...` (Skips flaky network tests)
- **Schema**: `maknoon schema` (Generates JSON metadata for agents)

## 🚀 v3.0 Roadmap (Industrial-Grade Refactor)
*The following tasks are pending implementation (see `.agents/plans/v3-architecture-roadmap.md`):*

1.  **Strong Error Typing**: Transition from `fmt.Errorf` to concrete error structs (e.g., `ErrPolicyViolation`) in `pkg/crypto/errors.go`.
2.  **The Observer Pattern**: Replace `ProgressReader` with an asynchronous `EngineEvent` stream for decoupled telemetry.
3.  **The Decorator Pattern**: Refactor monolithic pipelines into a chain of `Transformer` middleware (Archive, Compress, Encrypt).
4.  **Registry Factory**: Replace hardcoded identity registries with a pluggable registration system.

## 🧪 Current Status
- **Agent Sandbox**: Fully Sealed (v1.5 Security Audit verified).
- **Architecture**: V2 (Policy-Driven Engine) completed.
- **Phase 1 of V3**: Started (Errors defined, migration pending).
