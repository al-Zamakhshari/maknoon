# Maknoon (مكنون) 🛡️

[![Release](https://img.shields.io/github/v/release/al-Zamakhshari/maknoon)](https://github.com/al-Zamakhshari/maknoon/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/al-Zamakhshari/maknoon)](https://goreportcard.com/report/github.com/al-Zamakhshari/maknoon)

**Maknoon** (Arabic: مكنون) translates to *the hidden*, *the concealed*, or *that which is carefully preserved*. 

Maknoon is a high-performance, post-quantum CLI encryption tool. It combines modern cryptographic standards with a hyper-efficient streaming architecture to protect your data with absolute care.

## ✨ Core Philosophies & Design Choices

1.  **Post-Quantum Readiness (ML-KEM/ML-DSA):** Maknoon uses **NIST-standardized** Post-Quantum algorithms (Kyber1024 and Dilithium87) to ensure data remains secure against future quantum threats.
2.  **Streaming Architecture (Hyper-Efficiency):** Using a **64KB chunk-based pipeline**, Maknoon maintains a **constant memory footprint** regardless of file size (MBs to TBs).
3.  **Strict Memory Hygiene:** Passphrases, raw keys, and sensitive buffers are **explicitly zeroed out** from RAM immediately after use.
4.  **Authenticated Encryption (XChaCha20-Poly1305):** Every chunk is independently authenticated, ensuring immediate detection of tampering.
5.  **Multi-Recipient Support:** Encrypt a single file for multiple recipients. Any authorized private key can decrypt the payload.
6.  **Modular Architecture:** A robust **Profile** system allows for seamless algorithm agility and custom security suites.

---

## 🚀 Getting Started

### Installation

**Using Homebrew (macOS/Linux):**
```bash
brew tap al-Zamakhshari/tap
brew install maknoon
```
**Gemini CLI Extension (for AI Agents):**
```bash
gemini-cli extension install https://github.com/al-Zamakhshari/maknoon --path extensions/maknoon-extension
```

**MCP Server (Model Context Protocol):**
Maknoon includes a native Go-based MCP server for integration with Claude Desktop, IDE extensions, and other AI tools.
```bash
go run ./integrations/mcp
```

**From Source:**
### 1. Identity & Key Management
```bash
# Generate a Post-Quantum identity
maknoon keygen -o my_id

# List your identities
maknoon identity list

# Show identity details (Hardware binding, etc.)
maknoon identity show my_id

# Rename an identity
maknoon identity rename my_id work_id
```

### 2. Encryption & Inspection
```bash
# Encrypt for a single recipient
maknoon encrypt secret.pdf -p work_id.kem.pub

# Encrypt for multiple recipients (Team Mode)
maknoon encrypt secret.pdf -p user1.pub -p user2.pub -p user3.pub

# Inspect file metadata without decrypting
maknoon info secret.pdf.makn
```

### 3. Password Vault (Quantum-Resistant)
```bash
# Store a secret
maknoon vault set github.com --user myname

# Retrieve
maknoon vault get github.com

# Rename or Delete vaults
maknoon vault rename default backup_vault
maknoon vault delete old_vault
```

---

## 🤖 Agentic AI Integration
Maknoon is **Agent-Ready** with strict JSON output and non-interactive environment triggers.

### Agent Handshake
If `MAKNOON_AGENT_MODE=1` is set, Maknoon automatically switches to JSON mode whenever its output is piped or redirected (not a TTY), allowing for seamless "zero-config" agent integration.

```bash
# Automated discovery and encryption
export MAKNOON_AGENT_MODE=1
maknoon identity active | jq .
```

---

## 🏗 Security Architecture

### Path & Overwrite Protection
Safety checks prevent accidental file overwrites. Use the `--overwrite` flag to bypass.

### Access Control
In JSON/Agent mode, vault access is strictly restricted to the default directory (`~/.maknoon/vaults`) to prevent unauthorized file-system probes.

### RAM Security
All sensitive cryptographic material is stored in `[]byte` and zeroed out using `SafeClear` patterns immediately after its operational lifecycle.

---

## 📜 License
This project is licensed under the MIT License.
