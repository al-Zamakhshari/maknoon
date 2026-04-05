# Maknoon (مكنون) 🛡️

**Maknoon** (Arabic: مكنون) translates to *the hidden*, *the concealed*, or *that which is carefully preserved*. 

Maknoon is a versatile, ultra-efficient CLI encryption tool designed for a post-quantum world. It combines bleeding-edge cryptographic standards with a high-performance streaming architecture to protect your files and directories with absolute care.

## ✨ Core Philosophies

1.  **Bleeding-Edge Security:** Uses hybrid cryptographic schemes (ML-KEM/Kyber1024), preparing your data for the future of quantum computing.
2.  **Hyper-Efficiency:** Processes massive files (100GB+) and complex directories with a **constant memory footprint** (~64KB).
3.  **Memory Hygiene:** Strictly adheres to the "Carefully Preserved" ethos by explicitly zeroing out all sensitive data (passphrases, keys, secrets) from RAM immediately after use.
4.  **Transparent Archiving:** Encrypts entire directories on-the-fly using streaming TAR integration.
5.  **High-Speed Compression:** Optional Zstd compression support to significantly reduce file size before encryption.
6.  **Modern DX:** Intuitive CLI with real-time progress feedback, automation support, and automatic header detection.

---

## 🛠 Technical Stack

*   **Symmetric Encryption:** XChaCha20-Poly1305 (Fast, authenticated encryption).
*   **Key Derivation:** Argon2id (Memory-hard, GPU-resistant).
*   **Compression:** Zstd (High-performance streaming compression).
*   **Post-Quantum KEM:** ML-KEM / Kyber1024 (NIST-standardized quantum resistance).
*   **Streaming:** Chunked AEAD (64KB blocks) with memory-efficient piping.

---

## 🚀 Getting Started

### Installation

Requires Go 1.21+

```bash
git clone https://github.com/a-khallaf/maknoon.git
cd maknoon
go build -o maknoon ./cmd/maknoon
```

### 1. Key Generation (Post-Quantum)
Generate a Kyber1024 keypair. By default, your private key is protected with an Argon2id-derived passphrase.

```bash
# Standard interactive mode
./maknoon keygen -o id_identity

# Automation mode (unprotected key)
./maknoon keygen --no-password -o id_automation
```

### 2. Encryption

**Passphrase Mode:**
```bash
./maknoon encrypt sensitive_report.pdf
```

**Compressed Mode:**
```bash
./maknoon encrypt large_log.txt --compress
```

**Directory/Archive Mode:**
```bash
./maknoon encrypt ./my_project_folder
```

**Asymmetric (Public Key) Mode:**
```bash
./maknoon encrypt massive_data.iso --pubkey id_identity.pub
```

### 3. Decryption
Maknoon automatically detects the encryption type (Symmetric vs. Asymmetric), the content type (File vs. Archive), and whether compression was used.

```bash
./maknoon decrypt massive_data.iso.makn
```

---

## 🤖 Automation & CI/CD

Maknoon is designed for headless environments. You can bypass interactive prompts using flags or environment variables.

### Environment Variables (Recommended)
```bash
export MAKNOON_PASSPHRASE="your-secret-key"
./maknoon encrypt ./deploy_artifacts
```

### Command Flags
```bash
./maknoon decrypt secret.makn --passphrase "my-password"
```

---

## 🏗 Architecture & Security

### AEAD Streaming
Each 64KB chunk is encrypted with a unique nonce derived from a per-file random base and a 64-bit counter. This prevents nonce-reuse while allowing for bit-perfect restoration of multi-terabyte files.

### "Carefully Preserved" RAM
Sensitive data is never left to the garbage collector. Maknoon uses `defer` blocks to explicitly overwrite byte slices containing passphrases and raw keys with zeros as soon as the cryptographic operations are finished.

### Verified Integrity
The project includes a robust integration test suite verifying symmetric, asymmetric, compression, and directory-based round-trips.
```bash
go test -v ./...
```

---

## 📜 License
This project is licensed under the MIT License.
