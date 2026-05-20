# CLI Command Reference
> **Technical Specification for the Maknoon Command-Line Interface**

## Executive Summary
The Maknoon CLI provides a unified interface for post-quantum cryptographic operations, identity management, and secure secret storage. Designed for both interactive use and automated integration, the interface supports structured JSON output and follows a deterministic command hierarchy governed by the Viper configuration framework.

---

## Agent Orchestration (MCP)
Maknoon serves as a native Model Context Protocol (MCP) server, allowing AI agents to perform cryptographic operations through standardized tool calls.

| Command | Functionality | Key Parameters |
| :--- | :--- | :--- |
| `mcp` | Launches the MCP server gateway. | `--transport`, `--address`, `--tls-cert`, `--tls-key` |

### MCP Transport Flags
*   **`--transport`**: Specifies the communication protocol. Options: `stdio` (default), `sse`.
*   **`--address`**: The network address for SSE mode (default: `:8080`).
*   **`--tls-cert`**: Path to the TLS certificate for secure SSE communication.
*   **`--tls-key`**: Path to the TLS private key for secure SSE communication.

---

## Cryptographic Operations
These commands manage the primary data protection pipeline, including hybrid encryption, digital signatures, and metadata analysis.

| Command | Functionality | Key Parameters |
| :--- | :--- | :--- |
| `encrypt` | Protects files/directories using the streaming engine. | `--public-key`, `--sign-key`, `--stealth`, `--compress` |
| `decrypt` | Restores encrypted assets using private identities. | `--private-key`, `--output`, `--overwrite` |
| `info` | Provides deep technical metadata for encrypted files. | `--json` |
| `sign` | Generates a standalone ML-DSA-87 signature. | `--identity`, `--output` |
| `verify` | Validates data integrity and provenance. | `--public-key`, `--signature` |
| `fragment` | Disperses a file into erasure-coded shards. | `--shards`, `--threshold`, `--out`, `--chunk-size` |
| `reassemble` | Reconstructs a file from fragments. | `--out`, `--verify` |
| `gen password` | Generates a CSPRNG password; prints entropy to stderr. | `--length` (default 32), `--no-symbols`, `--min-entropy`, `--store`, `--vault`, `--username`, `--overwrite`, `--passphrase` |
| `gen passphrase` | Generates a mnemonic passphrase from a 1885-word list (≈10.9 bits/word); prints entropy to stderr. | `--words` (default 6), `--separator`, `--min-entropy`, `--store`, `--vault`, `--username`, `--overwrite`, `--passphrase` |

---

## Configuration Management (Viper)
Maknoon uses the **Viper** framework to manage configuration across flags, environment variables, and configuration files.

### Precedence Hierarchy
1.  **Command Flags** (e.g., `--passphrase "secret"`)
2.  **Environment Variables** (prefixed with `MAKNOON_`, e.g., `MAKNOON_PASSPHRASE`)
3.  **Config File** (`config.json` or `.maknoon.yaml`)
4.  **Internal Defaults**

### Common Environment Variables
| Variable | Configuration Key | Description |
| :--- | :--- | :--- |
| `MAKNOON_AGENT_MODE` | `agent_mode` | Activates JSON output and security sandbox. |
| `MAKNOON_PASSPHRASE` | `passphrase` | Master key for vault and identity unlocking. |
| `MAKNOON_MCP_TRANSPORT`| `mcp.transport` | Default transport mode for the MCP server. |
| `MAKNOON_PERF_CONCURRENCY`| `perf.concurrency` | Number of parallel worker threads. |

---

## Identity Management
Maknoon utilizes a decentralized identity model based on NIST-standardized PQC algorithms.

| Command | Functionality | Key Parameters |
| :--- | :--- | :--- |
| `keygen` | Provisions a new hybrid PQC identity pair. | `--profile` (`nist`\|`conservative`), `--output` |
| `identity active` | Enumerates locally managed cryptographic identities. | `--json` |
| `identity info` | Shows key details: KEM public key, SIG public key, peer ID fingerprint. | `--json` |
| `identity publish` | Publishes public keys to WKD (HTTPS) or DNS. | `--wkd` (default), `--dns`, `--desec`, `--local` |
| `identity shard` | Splits a generic secret into Shamir shards (SSS). | `--threshold`, `--shares` |
| `identity reconstruct` | Rebuilds a secret from threshold shards. | `--json` |
| `identity split` | Shards a private identity file via Shamir's Secret Sharing. | `--threshold`, `--shares` |
| `identity combine` | Reconstructs a private identity from M-of-N mnemonics. | `--output` |

---

## Secret Vault Operations
The vault provides an authenticated, quantum-resistant storage layer for credentials and sensitive configuration data.

| Command | Functionality | Key Parameters |
| :--- | :--- | :--- |
| `vault set` | Stores a credential with optional username association. | `--user`, `--vault` |
| `vault get` | Retrieves a managed secret from the storage layer. | `--vault` |
| `vault list` | Displays services stored within the active vault. | `--json` |
| `vault split` | Shards the master vault access material. | `--threshold`, `--shares` |
| `vault recover` | Restores vault access using reconstructed material. | `--output` |
| `vault export` | Exports all entries as an encrypted .makn bundle for migration. | `--output`, `--vault` |
| `vault import` | Imports entries from an encrypted .makn bundle. | `--input`, `--vault`, `--overwrite` |

---

## System Utilities
Administrative commands for system configuration, capability discovery, and cryptographic profiling.

| Command | Functionality | Key Parameters |
| :--- | :--- | :--- |
| `config` | Manages global security and performance settings. | `list`, `set`, `init` |
| `profiles` | Lists built-in profiles (`nist`=1, `conservative`=3) and manages custom profiles. | `list`, `gen`, `rm` |
| `session derive` | Derives a reusable session key from a passphrase (skips per-file KDF in bulk ops). | `--passphrase` |
| `call <tool>` | CLI MCP client — invokes a tool on a running Maknoon SSE server. | `--addr`, `--args`, `--insecure` |
| `audit verify` | Verifies the hash-chain integrity of the audit log. | `(No parameters)` |
| `schema` | Generates a recursive JSON-Schema of the CLI. | `(No parameters)` |
| `man` | Generates technical manual pages (roff/man format). | `(No parameters)` |

---

## Testing and Verification
For developers and auditors, Maknoon provides standardized testing hooks.

*   **Fast Suite**: Run `go test -short ./...` to execute core logic while skipping network-dependent tests.
*   **Mission Suite**: Integration tests that verify behavioral consistency across all transport modes (CLI, Stdio, SSE).
