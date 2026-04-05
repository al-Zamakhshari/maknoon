# Maknoon (مكنون) 🛡️

[![Release](https://img.shields.io/github/v/release/a-khallaf/maknoon)](https://github.com/a-khallaf/maknoon/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/a-khallaf/maknoon)](https://goreportcard.com/report/github.com/a-khallaf/maknoon)

**Maknoon** (Arabic: مكنون) translates to *the hidden*, *the concealed*, or *that which is carefully preserved*. 

Maknoon is a versatile, ultra-efficient CLI encryption tool designed for a post-quantum world. It combines bleeding-edge cryptographic standards with a high-performance streaming architecture to protect your files and directories with absolute care.

## ✨ Core Philosophies

1.  **Bleeding-Edge Security:** Uses hybrid cryptographic schemes (ML-KEM/ML-DSA), preparing your data for the future of quantum computing.
2.  **Hyper-Efficiency:** Processes massive files (100GB+) and complex directories with a **constant memory footprint** (~64KB).
3.  **Memory Hygiene:** Strictly adheres to the "Carefully Preserved" ethos by explicitly zeroing out all sensitive data (passphrases, keys, secrets) from RAM immediately after use.
4.  **Post-Quantum Signatures:** Provides non-repudiation and integrity using ML-DSA (Dilithium) signatures.
5.  **Transparent Archiving:** Encrypts entire directories on-the-fly using streaming TAR integration.
6.  **High-Speed Compression:** Optional Zstd compression support.
7.  **Modern DX:** Intuitive CLI with real-time progress feedback, automation support, and automatic header detection.

---

## 🛠 Technical Stack

*   **Symmetric Encryption:** XChaCha20-Poly1305 (Fast, authenticated encryption).
*   **Key Derivation:** Argon2id (Memory-hard, GPU-resistant).
*   **Compression:** Zstd (High-performance streaming compression).
*   **Post-Quantum KEM:** ML-KEM / Kyber1024 (NIST-standardized encryption).
*   **Post-Quantum SIG:** ML-DSA-87 / Dilithium (NIST-standardized signatures).
*   **Vault Storage:** bbolt (Pure-Go persistent key-value store).

---

## 🚀 Getting Started

### Installation

**Using Homebrew (macOS/Linux):**
```bash
brew install a-khallaf/tap/maknoon
```

**From Source:**
Requires Go 1.21+
```bash
git clone https://github.com/a-khallaf/maknoon.git
cd maknoon
go build -o maknoon ./cmd/maknoon
```

### 1. Key Generation (Post-Quantum)
Generate a full Post-Quantum identity (Encryption + Signing keys).

```bash
# Generates id_identity.kem.{key,pub} and id_identity.sig.{key,pub}
./maknoon keygen -o id_identity
```

### 2. Encryption & Signing

**Passphrase Mode:**
```bash
./maknoon encrypt sensitive_report.pdf
```

**Asymmetric Mode (Public Key):**
```bash
./maknoon encrypt massive_data.iso --public-key id_identity.kem.pub
```

**Digital Signature:**
```bash
./maknoon sign document.pdf --private-key id_identity.sig.key
```

**Verify Signature:**
```bash
./maknoon verify document.pdf --public-key id_identity.sig.pub
```

### 3. Password Vault
Securely store and retrieve credentials in a quantum-resistant database.

```bash
./maknoon vault set github.com --user myname
./maknoon vault get github.com
```

---

## 🤖 Automation & CI/CD

Maknoon is designed for headless environments. You can bypass interactive prompts using flags or environment variables.

```bash
export MAKNOON_PASSPHRASE="your-secret-key"
./maknoon encrypt ./deploy_artifacts --compress
```

---

## 🏗 Architecture & Security

### AEAD Streaming
Each 64KB chunk is encrypted with a unique nonce derived from a per-file random base and a 64-bit counter. This prevents nonce-reuse while allowing for bit-perfect restoration of multi-terabyte files.

### "Carefully Preserved" RAM
Sensitive data is never left to the garbage collector. Maknoon uses `defer` blocks to explicitly overwrite byte slices containing passphrases and raw keys with zeros as soon as the cryptographic operations are finished.

### Verified Integrity
The project includes a robust integration test suite verifying symmetric, asymmetric, compression, signing, and directory-based round-trips.
```bash
go test -v ./...
```

---

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
