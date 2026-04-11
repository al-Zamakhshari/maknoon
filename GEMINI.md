# Maknoon (مكنون) - Project Context

Maknoon is a high-performance, post-quantum CLI encryption tool written in Go. It focuses on efficiency, security, and future-proofing against quantum computing threats.

## 🏗 Project Architecture

- **`cmd/maknoon/`**: Contains the entry point (`main.go`) and CLI command definitions using the Cobra library.
- **`pkg/crypto/`**: The core library implementing the cryptographic pipeline, streaming logic, and FIDO2 integration.
- **`third_party/`**: Any external dependencies managed locally or specific patched versions.

## 🛡 Cryptographic Stack

- **Symmetric Cipher**: XChaCha20-Poly1305 (AEAD) with 192-bit nonces.
- **Asymmetric Encryption (KEM)**: ML-KEM / Kyber1024 (NIST Standard).
- **Digital Signatures**: ML-DSA-87 / Dilithium (NIST Standard).
- **Key Derivation (KDF)**: Argon2id (Time: 3, Memory: 64MB).
- **Hardware Security**: FIDO2 (Passkey) support via a CGO-free implementation.

## 🛠 Building and Running

### Prerequisites
- Go 1.21 or higher.

### Key Commands
- **Build (Local)**: `go build -o maknoon ./cmd/maknoon`
- **Build (Release Simulation)**: `goreleaser release --snapshot --clean`
- **Test**: `go test ./...`
- **Run (Development)**: `go run ./cmd/maknoon`
- **Benchmark**: `go test -bench . ./pkg/crypto`

## 🚀 Pre-Release Checklist
Before every release or major push, the following steps **must** be completed:

1.  **Documentation Update**: Ensure `README.md` reflects all new features, flags, and architectural changes.
2.  **Man Page Update**: Sync `maknoon.1` with the current CLI state (commands and flags).
3.  **Test Verification**:
    *   Update **Unit Tests** in `pkg/crypto/` to cover new logic.
    *   Update **Integration Tests** in `cmd/maknoon/commands/stress_test.go` for end-to-end verification.
    *   Run the full suite: `go test -v ./...`.
4.  **Security Audit**:
    *   Check for path traversal vulnerabilities (Zip Slip).
    *   Ensure memory hygiene (`SafeClear`) is applied to all new sensitive data paths.
    *   Run `/security:analyze` if applicable.
5.  **Quality Check**:
    *   Ensure 100% `gofmt` compliance.
    *   Check cyclomatic complexity (keep under 15).
    *   Run `go vet ./...`.

- **Cryptographic Agility**: NEVER hardcode cryptographic algorithms or parameters (nonce sizes, salt sizes, etc.) in the core pipeline. All primitives MUST be accessed through the `CryptoProfile` interface. Maknoon supports Hybrid Profiles:
    - **Secret Profiles (3-127)**: Definitions stored in external JSON files.
    - **Portable Profiles (128-255)**: Definitions packed directly into the file header.
- **Memory Hygiene**: Always use `crypto.SafeClear` to zero out sensitive data (keys, passphrases) in memory immediately after use.
- **Streaming & Pipes**: Prefer `io.Reader` and `io.Writer` over file paths in command logic. All new encryption/decryption features MUST support standard I/O (stdin/stdout via `-`).
- **Automation First**: New flags and commands should support a `--quiet` mode to suppress progress bars and informational output for CI/CD and scripts.
- **Environment Integration**: Sensitive or repetitive inputs (keys, passphrases) should be resolvable via standard environment variables (`MAKNOON_*`).
- **CGO Avoidance**: Prefer pure-Go implementations to maintain easy cross-compilation and portability.
- **Documentation**: All exported functions and constants should have comments following the standard Go convention (`// Name ...`).
- **Post-Quantum Only**: NEVER fallback to classical algorithms (RSA/ECC) for primary protection. Any new asymmetric logic must use NIST-standardized Post-Quantum primitives.

## 🧪 Testing Practices

- **Unit Tests**: Found in `*_test.go` files alongside the source code.
- **Integration Tests**: Located in `cmd/maknoon/main_test.go` and `cmd/maknoon/commands/stress_test.go`, covering end-to-end CLI scenarios.
- **Mocking**: Use the `Authenticator` interface in `pkg/crypto/fido2.go` for hardware-dependent testing.
