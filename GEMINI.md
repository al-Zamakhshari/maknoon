# Maknoon (مكنون) - Project Context

Maknoon is an industrial-grade, post-quantum CLI encryption engine and Model Context Protocol (MCP) server. It focuses on functional density, cryptographic integrity, and secure AI agent orchestration.

## 🏗 Project Architecture (v3.0 - Industrial-Grade)

- **`Unified Binary`**: A single statically linked binary hosts both the CLI and the native MCP server. Mode of operation is determined by the `mcp` command.
- **`pkg/crypto/engine.go`**: The central stateful service. Enforcement of the **Capability-Based Sandbox** (AgentPolicy) occurs at the engine entry points.
- **`Dual-Transport MCP`**: Supports local `stdio` and remote `sse` (Server-Sent Events). Remote sessions are secured via **Post-Quantum TLS 1.3** (prioritizing ML-KEM).
- **`UI Service Pattern`**: Output management is decoupled from logic via the `UIHandler` struct, eliminating global environment hacks (like `GO_TEST`).
- **`Configuration`**: Standardized on **Viper**. Precedence: CLI Flags > Environment Variables > `config.json` > Defaults.
- **`Container Sandbox`**: Multi-stage `scratch` build (~13MB) with zero OS attack surface. Runs as a non-privileged user (`1000:1000`).

## 🛡 Cryptographic Stack

- **Symmetric Cipher**: XChaCha20-Poly1305 (AEAD) with 192-bit nonces.
- **Asymmetric Encryption (KEM)**: ML-KEM / Kyber1024 (NIST Standard) wrapped in standard **HPKE Seal/Open** (RFC 9180).
- **Digital Signatures**: ML-DSA-87 / Dilithium (NIST Standard).
- **Key Derivation (KDF)**: Argon2id (Standard: 3 iterations, 64MB memory).
- **Transport Security**: TLS 1.3 with native X25519MLKEM768 hybrid key exchange.

## 🤖 Agent Sandbox & Governance

1.  **Logical Isolation**: `AgentPolicy` restricts the engine to the user's workspace and temp directories, and blocks configuration persistence.
2.  **Physical Isolation**: Containerized deployment removes shells and utilities, trapping the process in an immutable sandbox.
3.  **Governance**: All state changes and cryptographic operations are logged with masked metadata via the `AuditEngine` decorator.

## 🚀 P2P & Identity Lessons (Post-Quantum Handshakes)

- **Identity Collision**: Never use `libp2p.FallbackDefaults` when providing a custom identity. This triggers a "cannot specify multiple identities" error in the libp2p host constructor.
- **Explicit Identity**: All P2P operations (`send`, `receive`, `chat`) must support explicit identity selection via the `--identity` flag (CLI) or `identity` argument (MCP). Never hardcode "default" for agent-orchestrated missions.
- **MCP-over-SSE Protocol**: Remember that in MCP SSE transport, tool responses are pushed through the long-lived SSE stream (`/sse`), not the POST body. Orchestration scripts must maintain an active SSE connection and filter the stream for matching JSON-RPC IDs.
- **Sandbox Provisioning**: In isolated environments (e.g., Docker `scratch`), identities must be proactively generated via `keygen --no-password` before P2P tools can bind to a transport.

## 📋 Engineering & Documentation Standards

### 0. The Skeptical Engineering Persona
- **Empirical Rigor**: Never assume a feature works just because it compiles or passed a shallow test. Demand high-fidelity E2E verification for all critical paths.
- **Dependency Suspicion**: Treat all third-party libraries (even core ones like libp2p) as potential sources of bloat, complexity, and failure. Always verify their impact on binary size and runtime behavior.
- **Proof of Failure**: Before applying a fix, you MUST empirically reproduce the failure. If a test is failing, do not "work around" it; diagnose the root cause until the failure state is understood and documented.
- **No Magic**: Distrust "magic" behavior. If a connection "just works" via NAT traversal, verify which relays were used and why.

### 1. The Engine Pattern
All business logic must be invoked via the `Engine` struct. UI layers (CLI/MCP) must remain strictly as controllers.

### 2. UI-Agnostic Design
Do not use `fmt.Print` or `os.Getenv` directly for business logic. Use the `UIHandler` and `Viper` accessors to maintain testability and consistency.

### 3. Testing Mandates
- **Universal Missions**: All integration tools must be verified by a transport-agnostic mission suite.
- **Isolation**: Use `testing.Short()` to skip network-dependent tests by default. 
- **Integrity**: Every new feature requires a functional smoke test and a policy-violation test.

### 4. Documentation Standards
All public-facing documentation must use objective, factual language and scannable formatting (tables/Mermaid diagrams).

## 🛠 Building and Running

### Key Commands (Makefile)
- **Build**: `make build` (Produces optimized 13MB stripped binary)
- **Test**: `make test` (Runs industry-standard fast suite)
- **Docker**: `make docker-build` (Generates OCI-compliant secure sandbox)

## 🧪 Current Status
- **Architecture**: V3 (Unified Binary & Dual-Transport) complete.
- **Testing**: 45+ cases (Unit, Integration, Fuzz, Remote Mission) verified.
- **Security**: OCI metadata and volume governance finalized.
