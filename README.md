# Maknoon (مكنون) 🛡️

[![Release](https://img.shields.io/github/v/release/al-Zamakhshari/maknoon)](https://github.com/al-Zamakhshari/maknoon/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/al-Zamakhshari/maknoon)](https://goreportcard.com/report/github.com/al-Zamakhshari/maknoon)

**Maknoon** (Arabic: مكنون) translates to *the hidden*, *the concealed*, or *that which is carefully preserved*. 

Maknoon is a high-performance, post-quantum CLI encryption tool. It combines modern cryptographic standards with a hyper-efficient streaming architecture to protect your data with absolute care.

## ✨ Core Philosophies & Design Choices

1.  **Post-Quantum Readiness (ML-KEM/ML-DSA):** Traditional RSA and ECC are vulnerable to future quantum threats. Maknoon uses **NIST-standardized** Post-Quantum algorithms (Kyber1024 and Dilithium87) to ensure long-term data security.
2.  **Streaming Architecture (Hyper-Efficiency):** Using a **64KB chunk-based pipeline**, Maknoon maintains a **constant memory footprint** regardless of file size. It can securely process multi-terabyte datasets on low-resource hardware.
3.  **Strict Memory Hygiene:** All passphrases, raw keys, and sensitive buffers are **explicitly zeroed out** from RAM immediately after use using `SafeClear` patterns to prevent leakage through memory forensics.
4.  **Authenticated Encryption (XChaCha20-Poly1305):** Every data chunk is independently authenticated, ensuring immediate detection of any bit-level corruption or tampering.
5.  **Transparent Directory Support:** Encrypts entire directory trees on-the-fly using an integrated streaming TAR encoder, avoiding intermediate unencrypted temporary files.
6.  **High-Speed Compression:** Optional **Zstd** integration provides superior compression ratios without sacrificing streaming performance.
7.  **Multi-Core Parallelism:** Automatically scales encryption/decryption across all available CPU cores for maximum throughput.
8.  **Hardware-Backed Security:** Supports FIDO2 security keys (e.g., YubiKey) for hardware-bound master keys via a **100% Pure Go** implementation.
9.  **Cryptographic Agility:** A modular **Profile** system allows for seamless migration to new standards while maintaining full backward compatibility.

---

## 🏗 Modular Architecture (Profiles)

Maknoon uses a **Suite/Profile** architecture. The first byte of every encrypted file identifies the `ProfileID`.

### 🛠 Profile Management
*   **Built-in 1 (Default):** XChaCha20-Poly1305 + NIST PQC.
*   **Built-in 2:** AES-256-GCM + NIST PQC.
*   **Custom:** Generate a randomized secure profile JSON:
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

# Protect your private keys with a hardware security key (YubiKey)
maknoon keygen --fido2 -o secure_id
```

### 2. Encryption & Signing

**Symmetric Mode (Passphrase):**
```bash
# Encrypt (will prompt for passphrase)
maknoon encrypt sensitive_report.pdf -o report.makn

# Decrypt 
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
```bash
# Generate a random 32-character password
maknoon gen password --length 32

# Generate a 6-word mnemonic passphrase
maknoon gen passphrase --words 6
```

### 4. Password Vault
Securely store credentials in a quantum-resistant database.

```bash
# Store a secret (prompts for secret via secure terminal)
maknoon vault set github.com --user myname

# Store a secret via environment variable (Agent Mode)
export MAKNOON_PASSWORD="your-secure-token"
maknoon vault set github.com --json

# Retrieve
maknoon vault get github.com
```

---

## 🤖 Agentic AI Integration

Maknoon is optimized for **Automated Workflows** and AI Agents. It features a strict JSON output mode and suppresses all interactive prompts.

### Key Features:
- **`--json` Flag**: Triggers structured JSON output and redirects interactive prompts to errors.
- **`MAKNOON_JSON=1`**: Global environment trigger for non-interactive mode.
- **Python Tool Wrapper**: A complete LangChain-ready implementation is available in `integrations/langchain/maknoon_agent_tool.py`.

### Example (Python):
```python
from integrations.langchain.maknoon_agent_tool import get_maknoon_secret

# Retrieve a secret from the vault
result = get_maknoon_secret.invoke({"service_name": "github"})
print(result['password'])
```

---

## 🏗 Security Architecture

### Path & Overwrite Protection
Maknoon includes safety checks to prevent accidental file overwrites. Decryption and profile generation will fail if the target file already exists, unless the `--overwrite` flag is provided.

### Access Control (JSON Mode)
To protect against unauthorized file access in automated environments, Maknoon restricts vault database locations to the default directory (`~/.maknoon/vaults`) when running in JSON mode.

### RAM Security
Sensitive data (passphrases, master keys, decrypted buffers) is stored in `[]byte` slices and explicitly zeroed out immediately after use to mitigate RAM-dump attacks.

---

## 🤖 Automation & CI/CD

```bash
# Set passphrase for headless environments
export MAKNOON_PASSPHRASE="your-vault-key"

# Pipe data directly into Maknoon
echo "Secret data" | maknoon encrypt - -o secret.makn --quiet

# Decrypt directly to stdout
maknoon decrypt secret.makn -o - --quiet
```

---

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
