# CLI Reference

Exhaustive guide to Maknoon's command-line interface.

## 🔑 Identity Management
Commands for managing Post-Quantum cryptographic identities.

### `maknoon keygen`
Generate a new Hybrid PQC identity.
*   `-o, --output`: Base name for key files (e.g., `work_id`).
*   `--no-password`: Do not protect the private key with a passphrase.

### `maknoon identity active`
Automatically discover and list the absolute paths of all available public keys on the system. Primarily used for AI agent discovery.

---

## 🔒 Protection & Restoration
Core commands for securing data.

### `maknoon encrypt [source]`
Encrypt a file or directory.
*   `-p, --public-key`: Path to the recipient's public key. Supports multiple `-p` for team mode.
*   `-s, --passphrase`: Use a password instead of a public key (symmetric mode).
*   `-c, --compress`: Enable Zstd compression.
*   `--stealth`: Enable fingerprint resistance (removes magic bytes).

### `maknoon decrypt [source]`
Decrypt and restore a Maknoon file.
*   `-k, --private-key`: Path to your private key.
*   `-s, --passphrase`: Passphrase for symmetric decryption.
*   `--stealth`: Must be provided if the file was encrypted in stealth mode.

---

## 🔐 Secret Vault
Manage an encrypted database of passwords and credentials.

### `maknoon vault set [service]`
Store a credential. Prompts for the password via a secure terminal.

### `maknoon vault get [service]`
Retrieve a credential from the vault. Requires the master passphrase.

---

## 🕵️ Metadata & Inspection
### `maknoon info [file]`
Inspect an encrypted file's metadata (Algorithm type, profile ID, flags) without performing decryption.
