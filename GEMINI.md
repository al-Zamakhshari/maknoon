# Maknoon (مكنون) - Project Context

Maknoon is a high-performance, post-quantum CLI encryption tool. It focuses on efficiency, security, and future-proofing against quantum computing threats.

## 🏗 Project Architecture

- **`cmd/maknoon/`**: Entry point (`main.go`) and CLI command definitions using Cobra.
- **`pkg/crypto/`**: Core library implementing the cryptographic pipeline, streaming logic, and FIDO2 integration.
- **`integrations/`**: Third-party wrappers and tools (e.g., Python/LangChain).

## 🛡 Cryptographic Stack

- **Symmetric Cipher**: XChaCha20-Poly1305 (AEAD) with 192-bit nonces.
- **Asymmetric Encryption (KEM)**: ML-KEM / Kyber1024 (NIST Standard).
- **Digital Signatures**: ML-DSA-87 / Dilithium (NIST Standard).
- **Key Derivation (KDF)**: Argon2id (Time: 3, Memory: 64MB).
- **Hardware Security**: FIDO2 (Passkey) support via a CGO-free pure-Go implementation.

## 🛠 Building and Running

### Prerequisites
- Go 1.25 or higher.

### Key Commands
- **Build (Local)**: `go build -o maknoon ./cmd/maknoon`
- **Build (Release Simulation)**: `goreleaser release --snapshot --clean`
- **Test**: `go test ./...`
- **Run (Development)**: `go run ./cmd/maknoon`
- **Quality Check**: `staticcheck ./... && go vet ./...`

## 🚀 Development Workflow

1.  **Dedicated Branching**: ALWAYS create a new dedicated feature branch (`feat/...`, `fix/...`, or `chore/...`) BEFORE committing any changes. Direct commits to `main` are strictly prohibited.
2.  **Pre-Push Requirements**: BEFORE pushing to the remote repository, you MUST:
    *   **Update Documentation**: Sync `README.md` and the `maknoon.1` man page with all changes.
    *   **Verify Tests**: Run the full test suite (`go test ./...`) and ensure a 100% pass rate.
    *   **Security Check**: Manually review or use `/security:analyze` to ensure no new vulnerabilities (PII leaks, Zip Slip, path traversal) are introduced.
3.  **Mandatory Pull Requests**: ALL changes MUST be submitted via a Pull Request from your dedicated branch to `main`.
4.  **Post-Push Monitoring**:
    *   **Monitor CI/CD**: After each push, actively monitor the GitHub Actions pipeline.
    *   **Automated Sync**: The CI/CD pipeline will automatically detect the next release version and sync the extension manifest directly to your Pull Request branch. You DO NOT need to create a second PR.
5.  **Merge Requirements**: Once the CI has automatically synced the manifest and all checks pass, you may merge the PR into `main`.

## 🚀 Pre-Release Checklist

1.  **Documentation Update**: Sync `README.md` and `maknoon.1` with all new features and security changes.
2.  **Test Verification**:
    *   Ensure **Unit Tests** in `pkg/crypto/` cover all new logic.
    *   Verify **Integration Tests** in `cmd/maknoon/commands/stress_test.go`.
    *   Run the full suite: `go test -v ./...`.
3.  **Security Audit**:
    *   Verify **Zip Slip** protection in `ExtractArchive`.
    *   Ensure **Memory Hygiene** (`SafeClear`) is applied to ALL sensitive buffers (passphrases, keys, PINs).
    *   Confirm **Access Control** logic for vault paths in JSON mode.
4.  **Quality Check**:
    *   Ensure 100% `gofmt` compliance.
    *   Check cyclomatic complexity (keep under 15 for core functions).
    *   Run `staticcheck ./...`.
    *   Verify that the **CI/CD workflow** (.github/workflows/ci.yml) is passing on main.

## 📋 Engineering Standards

- **Cryptographic Agility**: Use the `Profile` interface for all primitives. Support both Secret (3-127) and Portable (128-255) profiles.
- **Memory Hygiene**: Use `crypto.SafeClear` immediately after sensitive data use. Sensitive fields in structs (like passwords) must be `[]byte`.
- **Streaming & Pipes**: Prefer `io.Reader` and `io.Writer`. All commands MUST support standard I/O (stdin/stdout via `-`).
- **Automation & AI**: Maintain a strict `--json` output mode.
    - **Agent-Handshake**: Automatic JSON mode switch when `MAKNOON_AGENT_MODE=1` is set and output is not a TTY.
    - **Identity Discovery**: `maknoon identity active` outputs absolute paths of public keys in JSON format.
    - **MCP Server**: Native Model Context Protocol (MCP) server in `integrations/mcp` for cross-platform agentic workflows (Claude, Gemini CLI, IDEs).
    - **Interactive Suppression**: All interactive prompts are suppressed in JSON/Agent mode.
    - **Vault Isolation**: Restricted vault paths to `~/.maknoon/vaults` in Agent mode.
    - **Error Handling**: Return errors as JSON on `stderr`.
- **CGO Avoidance**: Maintain a 100% Pure Go codebase for maximum portability.
- **Python Tooling**: Keep `integrations/langchain/maknoon_agent_tool.py` updated with the latest CLI signature.

## 🧪 Testing Practices

- **Unit Tests**: Alongside source in `*_test.go`.
- **Integration Tests**: End-to-end CLI scenarios in `cmd/maknoon/main_test.go`.
- **Mocking**: Use the `Authenticator` interface for hardware testing.
