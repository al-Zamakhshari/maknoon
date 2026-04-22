# CLI Reference

## Core Commands

### `maknoon encrypt [file/dir]`
Encrypts a single file or an entire directory.
-   `--compress`, `-c`: Enable Zstd compression.
-   `--public-key`, `-p`: Encrypt for specific Post-Quantum recipients.
-   `--sign-key`: Integrated digital signature.
-   `--stealth`: Omit magic header bytes.
-   `--trust-on-first-use`: Automatically save resolved public keys to local contacts.

### `maknoon decrypt [file]`
Decrypts and restores data.
-   `--output`, `-o`: Specify target path (supports `-` for stdout).
-   `--overwrite`: Bypass safety check for existing files.
-   `--private-key`, `-k`: Path to your identity key.

### `maknoon send [file/dir]`
Sends data via secure ephemeral P2P (Magic Wormhole style).
-   Generates a human-readable **Code** and a **Session Passphrase**.
-   Works across networks and NATs.
-   `--text`: Send raw text instead of a file (Zero-Disk).
-   `--public-key`, `-p`: Encrypt for a specific recipient (Asymmetric mode).
-   `--stealth`: Enable stealth mode for the transfer.
-   `--trust-on-first-use`: Automatically save resolved public keys to local contacts.

### `maknoon receive [code]`
Receives data from a peer using a wormhole code.
-   Prompts for the **Session Passphrase** provided by the sender.
-   `--output`, `-o`: Specify where to save the data (use `-` for raw output).
-   `--private-key`, `-k`: Required for identity-based transfers.

### `maknoon chat [code]`
Opens a secure, real-time Ghost Chat session.
-   If no code is provided, you act as the host.
-   Supports TUI for human users.
-   Supports JSONL for AI agents.

### `maknoon info [file]`
Displays deep cryptographic metadata.
-   Outputs: Profile ID, Type (Symmetric/Asymmetric), KEM, SIG, and KDF details.
-   Use `--json` for automated parsing.

## Identity Management

### `maknoon keygen`
Generates a NIST-standard Post-Quantum identity.
-   Creates `.kem` and `.sig` key pairs.
-   Keys are protected by Argon2id.

### `maknoon identity active`
Lists all public keys available on the system. Optimized for AI agent discovery.

### `maknoon identity publish [handle]`
Anchors your active identity to a global registry for trustless discovery.
-   Defaults to **Nostr** relays.
-   `--nostr`: Explicitly publish to Nostr (Kind 0).
-   `--dns`: Generate a DNS TXT record.
-   `--desec`: Automatically publish to deSEC.io.
-   `--local`: Register only in the local database.

### `maknoon identity split [name]`
Shards a private identity using Shamir's Secret Sharing.
-   `-m`, `--threshold`: Minimum shares required (default: 2).
-   `-n`, `--shares`: Total shares to generate (default: 3).
-   `-s`, `--passphrase`: Passphrase to unlock the identity.

### `maknoon identity combine [mnemonics...]`
Reconstructs a private identity from mnemonic shards.
-   `-o`, `--output`: Name for the restored identity.
-   `-s`, `--passphrase`: Passphrase to protect the restored identity.

## Secret Management (Vault)

### `maknoon vault set [service]`
Securely stores a secret.
-   `--user`: Associate a username with the secret.
-   `--vault`: Specify a named vault database.

### `maknoon vault get [service]`
Retrieves a secret.

### `maknoon vault list`
Lists all stored services.

### `maknoon vault split`
Shards the vault's master access key.
-   `-m`, `--threshold`: Minimum shares required.
-   `-n`, `--shares`: Total shares to generate.

### `maknoon vault recover [shards...]`
Recovers vault contents using reconstructed access material.
-   `-o`, `--output`: Path to save recovered entries as a new vault.

## System Utilities

### `maknoon config [subcommand]`
Manages global Maknoon settings (relays, security, performance).
-   `list`: View active settings.
-   `set [key] [value]`: Update a specific setting.
    -   `default_identity`: Default identity name.
    -   `security.time`: Argon2id iterations.
    -   `security.memory`: Argon2id memory (KB).
    -   `security.threads`: Argon2id threads.
    -   `perf.concurrency`: Default parallel workers.
    -   `perf.stealth`: Default stealth mode.
    -   `nostr.relays`: Comma-separated Nostr relays.
    -   `nostr.metadata`: Toggle "Maknoon Enabled" note.
    -   `paths.keys`: Custom keys directory.
    -   `paths.vaults`: Custom vaults directory.
-   `init`: Initialize default config file.

### `maknoon profiles [subcommand]`
Manages custom cryptographic profiles (cipher, KDF, salt parameters).
-   `list`: View built-in and custom profiles with detailed parameters.
-   `gen [name]`: Generates a random, validated, and smoke-tested profile and saves it to the global config.
-   `rm [name]`: Removes a custom profile from the configuration.

### `maknoon schema`
Outputs a recursive JSON-Schema of every command and flag. Designed for autonomous AI agents to dynamically discover Maknoon's capabilities.
