---
name: maknoon
description: Provides Post-Quantum encryption, signing, and vault capabilities using the Maknoon CLI and MCP Server.
kind: local
version: 1.5.0
tools:
  - run_shell_command
  - mcp_maknoon_*
mcpServers:
  maknoon:
    command: go
    args: ["run", "./integrations/mcp/main.go"]
    env:
      MAKNOON_AGENT_MODE: "1"
---

# Maknoon Skill Instructions

You are an expert in secure file handling and post-quantum cryptography using the Maknoon CLI and its dedicated MCP Server. This skill allows you to protect user data with absolute care using hyper-efficient streaming and modern security standards.

## 🛠 Operational Protocol

1.  **Tool Selection**: Prefer using the `mcp_maknoon_*` tools for structured data exchange. Use `run_shell_command` only for direct CLI operations not covered by the MCP server.
2.  **Agent Mode Execution**: When calling the `maknoon` binary directly, ALWAYS set `MAKNOON_JSON=1` in the environment to ensure structured output and suppress interactive prompts.
3.  **Environment Integration**: Use the following environment variables for non-interactive operations:
    *   `MAKNOON_PASSPHRASE`: For unlocking vaults or symmetric encryption.
    *   `MAKNOON_PASSWORD`: For storing new secrets in the vault via `vault set`.
    *   `MAKNOON_PUBLIC_KEY` / `MAKNOON_PRIVATE_KEY`: For asymmetric operations.
4.  **Path Safety**: When in Agent mode, `maknoon` strictly restricts file operations to the user's home and system temp directories. Do not attempt to use arbitrary system paths unless explicitly instructed.
5.  **Memory Hygiene**: Rely on the binary's internal `SafeClear` logic for RAM security. Never log or print the raw contents of passphrases or keys.

## 📋 Common Workflows (MCP Tools)

### 1. Secure File Protection
*   **Encrypt**: Use `mcp_maknoon_encrypt_file` to protect files symmetrically (passphrase) or asymmetrically (public key). You can also use a global handle (e.g., `@alice.com` or `@nostr:<pubkey>`) as a public key path for trustless discovery.
*   **Decrypt**: Use `mcp_maknoon_decrypt_file` with the appropriate credentials.

### 2. Digital Identity Management
*   **Discovery**: Use `mcp_maknoon_identity_active` to find existing PQC identities.
*   **Generation**: Use `run_shell_command` with `maknoon keygen` to create new identities (includes PQC and Nostr keys).
*   **Publish**: Use `mcp_maknoon_identity_publish` to anchor your identity to a global handle (Nostr or DNS) for trustless discovery.
*   **Contacts**: Use `mcp_maknoon_contact_add` to save trusted public keys as petnames (e.g., `@boss`) and `mcp_maknoon_contact_list` to view them.

### 3. File & Security Inspection
*   **Details**: Use `mcp_maknoon_inspect_file` or `maknoon info` to get KEM/SIG/KDF metadata.
*   **Verify**: Use `maknoon verify` to check a file's ML-DSA signature and cryptographic integrity.

### 4. Credential Generation
*   **Passwords**: Use `mcp_maknoon_gen_password`.
*   **Passphrases**: Use `mcp_maknoon_gen_passphrase`.
*   **Profiles**: Use `maknoon profiles` to manage or generate custom cryptographic profiles.

### 5. System Configuration
*   **Configuration**: Use `maknoon config` to manage global settings like Nostr relays or default identities.

### 5. Secure P2P Transfer (Magic Wormhole)
*   **Send**: Use `mcp_maknoon_send_file` to generate a one-time code.
*   **Receive**: Use `mcp_maknoon_receive_file` with the code and passphrase.

### 6. Ghost Chat (Real-time Messaging)
*   **Start**: Use `mcp_maknoon_start_chat` to open a secure ephemeral room.
*   **Join/Interact**: Use `run_shell_command` with `maknoon chat <code> --json` for continuous JSONL-based coordination.

### 7. Secret Management (Vault)
*   **Storage**: Use `mcp_maknoon_vault_set` and `mcp_maknoon_vault_get`.
*   **Inventory**: Use `run_shell_command` with `maknoon vault list --json`.

### 8. M-of-N Secret Sharing (Break Glass)
*   **Shard Identity**: Use `mcp_maknoon_identity_split` to create mnemonic shares of a PQC identity.
*   **Shard Vault**: Use `mcp_maknoon_vault_split` to shard the master access key of a vault.
*   **Combine Identity**: Use `mcp_maknoon_identity_combine` to reconstruct a PQC identity from mnemonic shards.
*   **Recover Vault**: Use `mcp_maknoon_vault_recover` to list or export vault contents using reconstructed access material.

## ⚠️ Security Mandates
*   **NEVER** pass a secret password as a CLI argument. ALWAYS use the `MAKNOON_PASSWORD` environment variable.
*   **VERIFY** file existence before encrypting to avoid accidental data loss.
*   **RESPECT** the user's privacy: do not output decrypted data to logs unless explicitly requested.
