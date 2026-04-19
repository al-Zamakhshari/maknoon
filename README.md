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

### 3. Fingerprint Resistance (Stealth Mode)
Remove recognizable magic bytes from headers to provide deniability. The ciphertext becomes indistinguishable from random noise.
```bash
# Encrypt in stealth mode
maknoon encrypt secret.pdf -s "my-pass" --stealth

# Decrypt in stealth mode (requires --stealth)
maknoon decrypt secret.pdf.makn -o restored.pdf -s "my-pass" --stealth
```

### 4. Password Vault (Quantum-Resistant)
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

### 🚀 Quick Start (P2P Transfer)
No keys? No problem. Transfer files globally through NATs/Firewalls with Magic Wormhole transport and Maknoon security.

```bash
# 1. Send an entire directory (auto-archived)
maknoon send project-assets/

# 2. Send a one-time secret snippet (Zero-Disk transport)
maknoon send --text "API_KEY_12345"

# 3. Identity-based "one-click" P2P (Asymmetric)
maknoon send data.bin -p alice.pub
# Alice just runs: maknoon receive <code>
```

### 👻 Ghost Chat (Zero-Trace P2P Messaging)
Real-time, end-to-end encrypted messaging with no servers, no accounts, and zero logs. 

```bash
# Start a room
maknoon chat

# Join a room
maknoon chat 4-giant-pigeon
```

## 🤖 Agentic AI Integration
Maknoon is **Agent-Ready** with strict JSON output, non-interactive environment triggers, and a comprehensive integration suite.

### Agent Handshake
If `MAKNOON_AGENT_MODE=1` is set, Maknoon automatically switches to JSON mode whenever its output is piped or redirected (not a TTY), allowing for seamless "zero-config" agent integration.

```bash
# Automated discovery and encryption
export MAKNOON_AGENT_MODE=1
maknoon identity active | jq .
```

### 🔌 MCP Server (Model Context Protocol)
Maknoon includes a native Go-based MCP server for deep integration with **Claude Desktop**, IDE extensions (Cursor, VSCode), and other AI ecosystems.

**Available Tools:**
- `inspect_file`: Get deep cryptographic metadata (KEM/SIG/KDF details).
- `encrypt_file` / `decrypt_file`: Direct file protection.
- `gen_password` / `gen_passphrase`: High-entropy credential generation.
- `vault_get` / `vault_set`: Secure secret management.
- `identity_active`: Automated key discovery.

### 🐍 LangChain Integration
A Python-based toolkit is available in `integrations/langchain/` for building autonomous agents that can manage encryption and secrets.

```python
from maknoon_agent_tool import encrypt_maknoon_file, get_maknoon_file_info
# Agents can now autonomously verify file security before processing
info = get_maknoon_file_info.invoke({"file_path": "data.makn"})
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
