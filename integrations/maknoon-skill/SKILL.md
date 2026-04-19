---
name: maknoon
description: Provides Post-Quantum encryption, signing, and vault capabilities using the Maknoon CLI. Use when the user wants to "encrypt", "decrypt", "sign", "verify", or "store secrets" securely using NIST-standardized PQC (Kyber/Dilithium).
---

# Maknoon Skill Instructions

You are an expert in secure file handling and post-quantum cryptography using the Maknoon CLI. This skill allows you to protect user data with absolute care using hyper-efficient streaming and modern security standards.

## 🛠 Operational Protocol

1.  **Agent Mode Execution**: ALWAYS set `MAKNOON_JSON=1` in the environment when calling the `maknoon` binary to ensure structured output and suppress interactive prompts.
2.  **Environment Integration**: Use the following environment variables for non-interactive operations:
    *   `MAKNOON_PASSPHRASE`: For unlocking vaults or symmetric encryption.
    *   `MAKNOON_PASSWORD`: For storing new secrets in the vault via `vault set`.
    *   `MAKNOON_PUBLIC_KEY` / `MAKNOON_PRIVATE_KEY`: For asymmetric operations.
3.  **Path Safety**: When in JSON mode, `maknoon` strictly restricts vault paths to `~/.maknoon/vaults`. Do not attempt to use arbitrary paths for vaults unless explicitly instructed and safe.
4.  **Memory Hygiene**: Rely on the binary's internal `SafeClear` logic for RAM security. Never log or print the raw contents of passphrases or keys.

## 📋 Common Workflows

### 1. Secure File Protection
When asked to encrypt a file:
*   Identify the target recipient (Public Key) or ask for a passphrase.
*   Run: `MAKNOON_JSON=1 maknoon encrypt <input> -o <output> --json` (plus `-p` or `-s`).
*   Always use `--quiet` to keep logs clean unless debugging.

### 2. Digital Identity Management
When asked to manage keys:
*   Use `maknoon identity list --json` to discover available PQC identities.
*   Use `maknoon keygen` to generate new Post-Quantum identities if none exist.

### 3. File Inspection
When asked to check a file's security or details:
*   Run: `maknoon info <path> --json`
*   If the user mentions "stealth" or "headerless", add `--stealth`.

### 4. Credential Generation
When asked to generate a password or passphrase:
*   Password: `maknoon gen password --length <n> --json`
*   Passphrase: `maknoon gen passphrase --words <n> --json`

### 5. Secure P2P Transfer (Magic Wormhole)
When asked to send a file to another user or agent without pre-shared keys:
*   Use `maknoon send <path> --json` to generate a one-time code and session passphrase.
*   Provide the recipient with both the **Code** and the **Passphrase**.

When asked to receive a file:
*   Use `maknoon receive <code> --passphrase <passphrase> --json` to download and decrypt the file.

### 6. Secret Management (Vault)
When asked to store or retrieve secrets:
*   Use `maknoon vault list --json` to find existing entries.
*   Use `maknoon vault get <service> --json` to retrieve secrets.
*   Use `MAKNOON_PASSWORD=<secret> maknoon vault set <service> --json` to store secrets.

## ⚠️ Security Mandates
*   **NEVER** pass a secret password as a CLI argument. ALWAYS use the `MAKNOON_PASSWORD` environment variable.
*   **VERIFY** file existence before encrypting to avoid accidental data loss, though `maknoon` has internal protections.
*   **RESPECT** the user's privacy: do not output decrypted data to logs unless explicitly requested.
