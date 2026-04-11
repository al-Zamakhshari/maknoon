# Maknoon (مكنون) 🛡️

[![Release](https://img.shields.io/github/v/release/a-khallaf/maknoon)](https://github.com/a-khallaf/maknoon/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/a-khallaf/maknoon)](https://goreportcard.com/report/github.com/a-khallaf/maknoon)

**Maknoon** (Arabic: مكنون) translates to *the hidden*, *the concealed*, or *that which is carefully preserved*. 

Maknoon is a versatile, ultra-efficient CLI encryption tool designed for a post-quantum world. It combines bleeding-edge cryptographic standards with a high-performance streaming architecture to protect your files and directories with absolute care.

## ✨ Core Philosophies & Design Choices

1.  **Post-Quantum Readiness (ML-KEM/ML-DSA):** Traditional RSA and Elliptic Curve cryptography are vulnerable to future quantum computers (Shor's algorithm). Maknoon uses **NIST-standardized** Post-Quantum algorithms (Kyber1024 and Dilithium87) to ensure your data remains secure for decades, not just years.
2.  **Streaming Architecture (Hyper-Efficiency):** Unlike tools that load entire files into RAM, Maknoon uses a **64KB chunk-based streaming pipeline**. This ensures a **constant memory footprint** (~64KB) whether you are encrypting a 1MB PDF or a 1TB database backup.
3.  **Strict Memory Hygiene:** To prevent sensitive data leakage through memory forensics or swap files, Maknoon **explicitly zeros out** all passphrases and raw keys from RAM using `defer` blocks and `SafeClear` patterns immediately after use.
4.  **Authenticated Encryption (XChaCha20-Poly1305):** We chose XChaCha20-Poly1305 over AES-GCM for its superior performance in software-only environments and its resilience against nonce-misuse (due to its 192-bit extended nonce). Every chunk is independently authenticated, ensuring that any bit of corruption is detected immediately.
5.  **Transparent Directory Support:** Maknoon treats directories as first-class citizens. By integrating a **streaming TAR encoder** into the cryptographic pipeline, it encrypts entire directory trees on-the-fly without creating intermediate unencrypted temporary files.
6.  **High-Speed Compression:** Optional **Zstd** integration provides industry-leading compression ratios and speeds, perfectly suited for the streaming nature of the tool.
7.  **Multi-Core Parallelism:** Maknoon can parallelize chunk encryption and decryption across all available CPU cores using a high-performance worker pool, significantly reducing processing time for massive files without compromising data order.
8.  **Hardware-Backed Security (CGO-Free):** Maknoon supports FIDO2 security keys (like YubiKey) for hardware-backed master keys. Our implementation is **100% Pure Go**, ensuring seamless portability without external C dependencies.
9.  **Cryptographic Agility (Profile Architecture):** The tool is built on a modular "Profile" system. This allows for seamless migration to new cryptographic standards (like a future "v2" suite) without breaking backward compatibility or requiring monolithic code refactors.

---

## 🏗 Modular Architecture (Profiles)

Maknoon uses a **Suite/Profile** architecture. The first byte of every encrypted file (after the magic bytes) identifies the `ProfileID`.

- **Built-in Profiles:**
  - `ID 1`: NIST PQC (Kyber1024 + Dilithium87) with XChaCha20-Poly1305.
  - `ID 2`: NIST PQC with AES-256-GCM.
- **Secret Profiles (IDs 3-127):** Only the ID is stored in the header. The recipient **must** possess a matching JSON profile file to decrypt.
- **Portable Profiles (IDs 128-255):** The profile parameters (Cipher, KDF settings) are packed directly into the file header. No extra configuration is needed for decryption.

### Using Custom Profiles
You can define your own profile in a JSON file:
```json
{
  "id": 100,
  "cipher": 1,
  "kdf": 0,
  "kdf_iterations": 5,
  "kdf_memory": 131072,
  "kdf_threads": 4,
  "salt_size": 32,
  "nonce_size": 12
}
```
Encrypt using:
`./maknoon encrypt secret.txt --profile-file custom.json -s mypass`

---

## 🛠 Technical Stack & Rationale

| Component | Choice | Rationale |
| :--- | :--- | :--- |
| **Symmetric Cipher** | XChaCha20-Poly1305 | Modern AEAD; fast in software; 192-bit nonce for safety. |
| **KEM (Asymmetric)** | ML-KEM / Kyber1024 | NIST-standardized; Category 5 security (highest). |
| **Signature (SIG)** | ML-DSA-87 / Dilithium | NIST-standardized; robust non-repudiation. |
| **KDF** | Argon2id | Memory-hard and side-channel resistant; superior to PBKDF2. |
| **Compression** | Zstd | Modern, streaming-friendly, and extremely fast. |
| **Database** | bbolt | Embedded, ACID-compliant, and pure-Go for portability. |

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
Generate a full Post-Quantum identity (Encryption + Signing keys). By default, these are stored in `~/.maknoon/keys/`.

```bash
# Generates id_identity.kem.{key,pub} and id_identity.sig.{key,pub}
./maknoon keygen -o id_identity

# Protect your identity with a physical security key (YubiKey)
./maknoon keygen --fido2 -o secure_id
```

### 2. Encryption & Signing

**Symmetric Mode (Passphrase):**
Uses Argon2id for key derivation and XChaCha20-Poly1305 for encryption.
```bash
# Parallelize across all cores for maximum speed
./maknoon encrypt sensitive_report.pdf --concurrency 0
```

**Asymmetric Mode (Public Key):**
Uses ML-KEM-1024 to wrap a per-file ephemeral symmetric key.
```bash
./maknoon encrypt massive_data.iso --public-key id_identity.kem.pub
```

**Digital Signature & Verification:**
Provides non-repudiation using ML-DSA-87 (Dilithium).
```bash
# Sign
./maknoon sign document.pdf --private-key id_identity.sig.key

# Verify
./maknoon verify document.pdf --public-key id_identity.sig.pub
```

### 3. Password Vault
Securely store and retrieve credentials in a quantum-resistant database. The vault itself is protected by an Argon2id-derived master key or a hardware secret.

```bash
# Tie your vault to your physical YubiKey
./maknoon vault --fido2 set github.com --user myname

./maknoon vault get github.com
./maknoon vault list
```

---

## 🏗 Security Architecture

### Nonce Management
Each file starts with a random 192-bit base nonce. Every 64KB chunk XORs a 64-bit counter into this base. This architecture guarantees that **2^64 chunks** (approx. 1 zettabyte) can be safely encrypted per file without nonce collision risks.

### Metadata Privacy
Maknoon files include a minimal header containing:
1. Magic Bytes (Version detection)
2. 32-byte Salt (Argon2id)
3. 24-byte Base Nonce
4. Encryption Flags (Compression/Archive status)

No filenames or internal directory structures are leaked in the encrypted header; all metadata is contained within the encrypted payload.

---

## 🤖 Automation & CI/CD

Maknoon is designed for headless environments. You can bypass interactive prompts using flags, environment variables, or standard pipes.

```bash
# Set passphrase for automation
export MAKNOON_PASSPHRASE="your-secret-key"

# Use environment variables for keys
export MAKNOON_PUBLIC_KEY="/path/to/key.kem.pub"
export MAKNOON_PRIVATE_KEY="/path/to/key.kem.key"

# Pipe data directly into Maknoon (Standard I/O support)
echo "Secret data" | ./maknoon encrypt - -o secret.makn --quiet

# Decrypt directly to stdout
./maknoon decrypt secret.makn -o - --quiet
```

---

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
