# Maknoon (مكنون) - Project Context

Maknoon is a high-performance, post-quantum CLI encryption tool. It focuses on efficiency, security, and future-proofing against quantum computing threats.

## 🏗 Project Architecture

- **`cmd/maknoon/`**: Entry point (`main.go`) and CLI command definitions using Cobra. CLI commands should remain "thin," delegating logic to the service layer.
- **`pkg/crypto/`**: Core library implementing the cryptographic pipeline, streaming logic, and FIDO2 integration.
- **`integrations/`**: Third-party wrappers and tools (e.g., Python/LangChain, MCP Server).
- **`pkg/crypto/shares.go`**: Core Shamir's Secret Sharing engine with mnemonic support.
- **`pkg/crypto/registry.go`**: Identity Bridge interface and Bolt-based local registry.
- **`pkg/crypto/registry_nostr.go`**: Global discovery via Nostr Kind 0 metadata events.
- **`pkg/crypto/registry_dns.go`**: Global discovery via DNS TXT records (with deSEC support).
- **`pkg/crypto/contacts.go`**: Local Petname system for trusted peer management.

## 🛡 Cryptographic Stack

- **Symmetric Cipher**: XChaCha20-Poly1305 (AEAD) with 192-bit nonces.
- **Asymmetric Encryption (KEM)**: ML-KEM / Kyber1024 (NIST Standard).
- **Digital Signatures**: ML-DSA-87 / Dilithium (NIST Standard).
- **Key Derivation (KDF)**: Argon2id (Time: 3, Memory: 64MB).
- **Secret Sharing**: Shamir's SSS over $GF(2^8)$ with BIP-39 style mnemonics. Includes KEM, SIG, and Nostr keys.
- **Identity Discovery**: Global resolution via Nostr (`@nostr:npub...`) and DNS (`@domain.com`) with local Petname prioritization and self-signed record verification.
- **P2P Transport**: Magic Wormhole (SPAKE2 PAKE) layered with Maknoon Symmetric PQC.
 Supports **Identity-Based** (Asymmetric) handshakes, **Zero-Disk** text transport, and a **Sequenced Chat Protocol** with reordering buffers for rock-solid synchronization.

## 🤖 Agent Integration & Skills

- **"gh skill" Ready**: The project defines an official Agent Skill at `.github/skills/maknoon/SKILL.md`.
- **Inlined MCP Server**: The skill manifest includes a dedicated MCP server configuration (`go run ./integrations/mcp/main.go`) that agents can auto-provision.
- **Agent mode**: Triggered via `MAKNOON_AGENT_MODE=1` or `--json`. Suppresses all interactive prompts and forces structured JSON output.

## 📋 Engineering Standards & Design Patterns

### 1. Service Layer Pattern
Core business logic (handshakes, multi-stage pipelines) MUST reside in `pkg/crypto` and be exposed as reusable service functions.
- **`crypto.Protect`**: Orchestrates "Archive -> Compress -> Encrypt."
- **`crypto.Unprotect`**: Orchestrates "Decrypt -> Decompress -> Extract."
- **Goal**: Allow the core library to be used by TUIs, APIs, or Agents without CLI dependency.

### 2. Context Encapsulation
Avoid global variables for execution state. Use the `commands.Context` struct to manage `JSONOutput`, `JSONWriter`, and other session-specific states.
- Always use `commands.SetJSONOutput(bool)` to keep state synchronized.

### 3. Centralized Security Validation
All file system operations MUST be validated using `crypto.ValidatePath(path, restricted)`.
- **Restricted Mode**: (Triggered in Agent/JSON mode) Limits access to the user's Home and System Temp directories to prevent path traversal.

### 4. Identity & Contact Management
Use `crypto.ContactManager` for local address book operations and `crypto.IdentityRegistry` for global handle discovery.
- **Rule**: Always resolve local Petnames *before* falling back to the global dPKI registry.
- **Verification**: All remote identity records MUST be self-signed by the user's ML-DSA key and verified locally before use.

### 5. Memory Hygiene
Use `crypto.SafeClear` (aliased to `memguard.WipeBytes`) immediately after sensitive data use.
- **Critical**: Go's GC does not guarantee immediate erasure; deterministic wiping is mandatory for FEKs and passphrases.

### 7. Agentic Self-Description (Mandatory)
Maknoon MUST remain self-describing for autonomous agents. 
- **The `schema` Command**: Every new CLI command or flag MUST be automatically discoverable via `maknoon schema`. 
- **Metadata Requirement**: All commands MUST provide a concise `Short` description and a well-formed `Use` string (e.g., `command [optional] <required>`). 
- **Verification**: Changes to the CLI tree MUST be verified by running `go test ./cmd/maknoon/commands/schema_test.go`.

## 🛠 Building and Running

### Prerequisites
- Go 1.25 or higher.
- `uv` for Python integration tasks.

### Key Commands
- **Build**: `go build -o maknoon ./cmd/maknoon`
- **Test**: `go test ./...`
- **Python Tests**: `uv run python3 integrations/langchain/test_maknoon_agent_tool.py`

## 🚀 Development Workflow

1.  **Dedicated Branching**: ALWAYS create a new feature branch (`feat/...`, `fix/...`) BEFORE committing.
2.  **Pre-Push Requirements**:
    *   **Update Documentation**: Sync `README.md`, `maknoon.1`, and `wiki/`.
    *   **Verify Tests**: Ensure 100% pass rate on all Go and Python integration tests.
    *   **Formatting**: Run `gofmt -w .` project-wide.
3.  **Mandatory Pull Requests**: Direct commits to `main` are restricted. Changes must be verified via CI/CD before merging.

## 🚀 Pre-Release Checklist

1.  **Security Audit (v1.5 Status: COMPLETED)**:
    *   **Sharding Security**: Verified that $M-1$ shards yield zero information and that reconstructed buffers are wiped.
    *   **dPKI Integrity**: Confirmed that all published records are self-signed and verified via ML-DSA.
    *   **Path Traversal**: Verified that `ValidatePath` is applied to all file I/O commands (`encrypt`, `decrypt`, `info`, `sign`, `verify`).
    *   **Agent Isolation**: Confirmed that in Agent mode, all file operations are restricted to `~/` and system temp directories.
    *   **Zip Slip**: Verified protection in `ExtractArchive`.
    *   **Zero-Trace**: Confirmed use of `SafeClear` for FEKs and private keys.
    *   **JSON Redirection**: In `stdout` decryption, success metadata MUST go to `stderr`.
2.  **Quality Check**:
    *   Run `staticcheck ./...` and `go vet ./...`.
    *   Verify CI/CD success at [Actions](https://github.com/al-Zamakhshari/maknoon/actions).

## 🧪 Testing Practices

- **Unit Tests**: Alongside source in `*_test.go`.
- **Integration Tests**: End-to-end scenarios in `cmd/maknoon/main_test.go` and `integrations/`.
- **P2P Verification**: Use `pkg/crypto/p2p_test.go` to verify race-free header handling, zero-disk text transfers, and asymmetric identity-based handshakes.
