# Maknoon (مكنون) 🛡️

[![Release](https://img.shields.io/github/v/release/al-Zamakhshari/maknoon)](https://github.com/al-Zamakhshari/maknoon/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/al-Zamakhshari/maknoon)](https://goreportcard.com/report/github.com/al-Zamakhshari/maknoon)

**Maknoon** (Arabic: مكنون) translates to *the hidden*, *the concealed*, or *that which is carefully preserved*. 

Maknoon is a versatile, ultra-efficient CLI encryption tool designed for a post-quantum world. It combines bleeding-edge cryptographic standards with a high-performance streaming architecture to protect your files and directories with absolute care.

## ✨ Core Philosophies & Design Choices

1.  **Post-Quantum Readiness (ML-KEM/ML-DSA):** Traditional RSA and Elliptic Curve cryptography are vulnerable to future quantum computers (Shor's algorithm). Maknoon uses **NIST-standardized** Post-Quantum algorithms (Kyber1024 and Dilithium87) to ensure your data remains secure for decades, not just years.
2.  **Streaming Architecture (Hyper-Efficiency):** Unlike tools that load entire files into RAM, Maknoon uses a **64KB chunk-based streaming pipeline**. This ensures a **constant memory footprint** (~64KB) whether you are encrypting a 1MB PDF or a 1TB database backup.
3.  **Strict Memory Hygiene:** To prevent sensitive data leakage through memory forensics or swap files, Maknoon **explicitly zeros out** all passphrases, raw keys, and confirmation buffers from RAM using `SafeClear` patterns immediately after use.
4.  **Authenticated Encryption (XChaCha20-Poly1305):** We chose XChaCha20-Poly1305 for its superior performance in software-only environments and its resilience against nonce-misuse. Every chunk is independently authenticated, ensuring that any bit of corruption is detected immediately.
5.  **Transparent Directory Support:** Maknoon treats directories as first-class citizens. By integrating a **streaming TAR encoder** into the cryptographic pipeline, it encrypts entire directory trees on-the-fly without creating intermediate unencrypted temporary files.
6.  **High-Speed Compression:** Optional **Zstd** integration provides industry-leading compression ratios and speeds, perfectly suited for the streaming nature of the tool.
7.  **Multi-Core Parallelism:** Maknoon can parallelize chunk encryption and decryption across all available CPU cores using a high-performance worker pool.
8.  **Hardware-Backed Security (CGO-Free):** Maknoon supports FIDO2 security keys (like YubiKey) for hardware-backed master keys. Our implementation is **100% Pure Go**.
9.  **Cryptographic Agility (Profile Architecture):** Modular "Profile" system allows for seamless migration to new standards (IDs 3-127 for secret profiles, 128-255 for portable/self-contained profiles).

---

## 🏗 Modular Architecture (Profiles)

Maknoon uses a **Suite/Profile** architecture. The first byte of every encrypted file identifies the `ProfileID`.

### 🛠 Profile Management
*   **Built-in 1 (Default):** XChaCha20-Poly1305 + NIST PQC.
*   **Built-in 2:** AES-256-GCM + NIST PQC (Hardware Accelerated).
*   **Custom:** Generate a random secure profile and save to file:
    ```bash
    maknoon profiles --generate --secret --output my_suite.json
    ```

---

## 🚀 Getting Started

### Installation

**Using Homebrew (macOS/Linux):**
```bash
brew tap al-Zamakhshari/tap
brew install maknoon
```

**From Source:**
Requires Go 1.25+
```bash
git clone https://github.com/al-Zamakhshari/maknoon.git
cd maknoon
go build -o maknoon ./cmd/maknoon
```

### 1. Key Generation (Post-Quantum)
Generate a full Post-Quantum identity (Encryption + Signing keys).

```bash
# Generates id_identity.kem.{key,pub} and id_identity.sig.{key,pub}
maknoon keygen -o id_identity

# Protect your identity with a physical security key (YubiKey)
maknoon keygen --fido2 -o secure_id
```

### 2. Encryption & Signing

**Symmetric Mode (Passphrase):**
```bash
# Encrypt
maknoon encrypt sensitive_report.pdf -o report.makn

# Decrypt (will prompt for passphrase)
maknoon decrypt report.makn

# Decrypt and overwrite existing file
maknoon decrypt report.makn --overwrite
```

**Asymmetric Mode (Public Key):**
```bash
maknoon encrypt massive_data.iso --public-key recipient.pub
```

**Digital Signature & Verification:**
```bash
# Sign
maknoon sign document.pdf --private-key my.sig.key

# Verify
maknoon verify document.pdf --public-key my.sig.pub
```

### 3. High-Entropy Password Generation
Generate cryptographically secure passwords or mnemonics.

```bash
# Generate a 32-character password
maknoon gen password --length 32

# Generate a 6-word mnemonic passphrase
maknoon gen passphrase --words 6
```

### 4. Password Vault
Securely store credentials in a quantum-resistant database.

```bash
# Store a secret
maknoon vault set github.com "your-token-here" --user myname

# Retrieve
maknoon vault get github.com

# List all services
maknoon vault list
```

---

## 🤖 Agentic AI Integration

Maknoon is designed to be **Agent-Ready**. It features a strict JSON output mode and suppressed interactive prompts for seamless integration with LLM frameworks (LangChain, LangGraph, etc.).

### Key Features:
- **`--json` Flag**: Explicitly triggers structured JSON output and redirects interactive prompts to errors.
- **`MAKNOON_JSON=1`**: Environment variable for global non-interactive mode.
- **Python Tool Wrapper**: A complete LangChain-ready implementation is available in `integrations/langchain/maknoon_agent_tool.py`.

### Example (CLI):
```bash
export MAKNOON_PASSPHRASE="your_master_key"
maknoon vault get github --json
```

### Example (Python):
```python
from integrations.langchain.maknoon_agent_tool import get_maknoon_secret, generate_maknoon_password

# Generate a secure password for a new service
new_pass = generate_maknoon_password.invoke({"length": 24})

# Retrieve a secret
result = get_maknoon_secret.invoke({"service_name": "github"})
print(result['password'])
```

---

## 🏗 Security Architecture

### Path & Overwrite Protection
Maknoon includes safety checks to prevent accidental file overwrites. Decryption and profile generation will fail if the target file already exists, unless the `--overwrite` flag is explicitly provided.

### Metadata Privacy
Maknoon files include a minimal header. No filenames or internal directory structures are leaked; all metadata is contained within the encrypted payload.

---

## 🤖 Automation & CI/CD

```bash
# Set passphrase for headless environments
export MAKNOON_PASSPHRASE="your-secret-key"

# Pipe data directly into Maknoon
echo "Secret data" | maknoon encrypt - -o secret.makn --quiet

# Decrypt directly to stdout
maknoon decrypt secret.makn -o - --quiet
```

---

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
