# AI Agent and Automation Integration
> **Standardized Cryptographic Interface for Autonomous Systems**

## Executive Summary
Maknoon is designed for seamless integration with autonomous systems, Large Language Models (LLMs), and AI agents. By implementing the **Model Context Protocol (MCP)** and providing a self-describing command schema, Maknoon enables agents to perform complex cryptographic operations within a governed, machine-readable environment.

---

## Model Context Protocol (MCP) Integration
Maknoon operates as a native MCP server, supporting both local and remote transport protocols.

### Dual-Transport Support

| Transport | Implementation | Primary Use Case |
| :--- | :--- | :--- |
| **Stdio** | Standard I/O streams. | Local integration with Cursor, VS Code, and Desktop agents. |
| **SSE** | Server-Sent Events (HTTPS). | Remote agentic microservices and cloud-native gateways. |

### SSE Transport Security (PQ-TLS 1.3)
Remote MCP sessions are secured using **Post-Quantum TLS 1.3**. This integration provides a significant Security ROI by protecting agent communications against "Store Now, Decrypt Later" (SNDL) attacks.

```mermaid
sequenceDiagram
    participant Agent as AI Agent (Remote)
    participant TLS as PQ-TLS 1.3 Tunnel
    participant MCP as Maknoon MCP Server
    participant Eng as Engine Core (Sandbox)
    
    Note over Agent, Eng: 1. Transport Layer Security (Post-Quantum)
    Agent->>TLS: Client Hello (ML-KEM Hybrid)
    TLS->>Agent: Server Hello (X25519MLKEM768)
    Note right of TLS: Tunnel established with NIST PQC
    
    Note over Agent, Eng: 2. Protocol Handshake
    Agent->>MCP: initialize (JSON-RPC)
    MCP-->>Agent: server_info (v1.3.2)
    
    Note over Agent, Eng: 3. Governed Task Execution
    Agent->>MCP: tools/call (vault_get)
    MCP->>Eng: Policy Check (ValidatePath)
    Eng-->>MCP: Secret Payload
    MCP-->>Agent: Encrypted Response
```

*   **Hybrid Key Exchange**: Combines `X25519` (classical) and `ML-KEM-768` (quantum-resistant).
*   **Authentication**: Server identities are validated using standard TLS certificates, with the option for PQC-signed client certificates in future releases.
*   **Zero-Configuration Safety**: The server defaults to the highest security parameters when `--tls-cert` and `--tls-key` are provided.

---

## Configuration Example (Claude Desktop)

### Local Stdio Mode
To register Maknoon for local use:

```json
{
  "mcpServers": {
    "maknoon": {
      "command": "maknoon",
      "args": ["mcp", "--transport", "stdio"],
      "env": {
        "MAKNOON_AGENT_MODE": "1"
      }
    }
  }
}
```

### Remote SSE Mode
To connect to a remote Maknoon gateway:

```json
{
  "mcpServers": {
    "maknoon-remote": {
      "command": "npx",
      "args": ["@modelcontextprotocol/client-sse", "https://maknoon.example.com/sse"]
    }
  }
}
```

---

## Launching the MCP Server

### Stdio Gateway (Default)
```bash
maknoon mcp
```

### Secure SSE Gateway
```bash
maknoon mcp --transport sse --address :8443 --tls-cert server.crt --tls-key server.key
```

---

## Automated Agent Handshake
Maknoon implements an automated detection mechanism to transition into machine-readable (JSON) output modes, ensuring compatibility with automated pipelines.

The engine activates **Agent Mode** when the following condition is met:
*   **Environment Variable**: `MAKNOON_AGENT_MODE=1` is explicitly set.
*   **Command Invocation**: The `mcp` command is executed (automatically sets `agent_mode=1`).

---

## Sandboxed Container Deployment
For maximum security in production AI environments, Maknoon should be deployed as a containerized sandbox. This provides process-level isolation, preventing an AI agent from accessing any sensitive data outside the explicitly mounted workspace.

### Docker Implementation
Maknoon utilizes a **multi-stage build** starting from an empty `scratch` image, resulting in a minimal (~13MB) container with **zero OS-level attack surface**.

```bash
# Launch a physically isolated sandbox with Stdio MCP
docker run -v ~/workspace:/home/maknoon -e MAKNOON_AGENT_MODE=1 maknoon-sandbox
```

### Filesystem Governance
When operating in a containerized sandbox, Maknoon enforces strict path validation:
*   **Permitted**: `/home/maknoon` (and subdirectories), `/tmp/maknoon`.
*   **Prohibited**: System directories, root-level sensitive paths, and dotfiles outside the workspace.

---

## Environment Configuration (Viper-Based)
The following variables govern the behavior of Maknoon in automated and non-interactive environments.

| Variable | Description |
| :--- | :--- |
| `MAKNOON_AGENT_MODE` | Activates structured JSON output and non-interactive prompts. |
| `MAKNOON_PASSPHRASE` | Supplies the master key for vault and identity unlocking. |
| `MAKNOON_PRIVATE_KEY` | Specifies the path to the primary private identity file. |
| `MAKNOON_PUBLIC_KEY` | Sets the default recipient path for encryption tasks. |

> **Note:** All environment variables are prefixed with `MAKNOON_` and map to configuration keys using underscores (e.g., `mcp.transport` maps to `MAKNOON_MCP_TRANSPORT`).

---

## Environment Configuration
The following variables govern the behavior of Maknoon in automated and non-interactive environments.

| Variable | Description |
| :--- | :--- |
| `MAKNOON_AGENT_MODE` | Activates structured JSON output and non-interactive prompts. |
| `MAKNOON_PASSPHRASE` | Supplies the master key for vault and identity unlocking. |
| `MAKNOON_PASSWORD` | Sets the default secret for credential management operations. |
| `MAKNOON_PRIVATE_KEY` | Specifies the path to the primary private identity file. |
| `MAKNOON_PUBLIC_KEY` | Sets the default recipient path for encryption tasks. |

## Tool Specification Reference
Maknoon is fully self-describing. AI Agents can query the current tool registry and schema dynamically to understand the available cryptographic capabilities.

```bash
# Generate machine-readable tool schema (JSON)
go run ./cmd/maknoon schema 2>/dev/null > docs/integration/TOOL-REFERENCE.json
```


| Tool Name | Category | Description |
| :--- | :--- | :--- |
| `encrypt_file` | Crypto | Multi-recipient PQC encryption; supports directories and comma-separated key handles. |
| `decrypt_file` | Crypto | Asymmetric or symmetric decryption with optional sender verification. |
| `sign_file` / `verify_file` | Crypto | ML-DSA-87 signing and M-of-N threshold verification. |
| `shred_file` | Crypto | Secure deletion (multi-pass overwrite + random rename). |
| `vault_get` / `vault_set` | Vault | Encrypted secret storage with Argon2id key derivation. |
| `vault_set_blob` / `vault_get_blob` | Vault | Encrypted agent memory (persists across sessions). |
| `vault_status` | Vault | Quorum vault health and shard readiness. |
| `fragment_file` / `reassemble_file` | Dispersal | Reed-Solomon erasure coding; compose with rclone for cloud distribution. |
| `identity_publish` | Identity | Publish to WKD (HTTPS) or DNS; `registry` field: `wkd` (default), `dns`, `desec`, `local`. |
| `resolve_identity` | Identity | Resolve a petname or `@handle` to raw public key bytes. |
| `audit_verify` | Config | Verify hash-chain integrity of the forensic audit log. |
| `diagnostic` | Config | Full engine and environment manifest — call first to orient an agent. |
| `config_update` | Config | Live-update engine settings (profile, concurrency, stealth mode). |
| `gen_passphrase` | Crypto | Mnemonic passphrase from 1885-word list; response includes `entropy_bits` and `entropy_bits_pq`; optional `store_service`/`store_vault` writes directly to vault. |
| `gen_password` | Crypto | CSPRNG character password; response includes `entropy_bits` and `entropy_bits_pq`; optional `store_service`/`store_vault` writes directly to vault. |


---

## Governance & Compliance
