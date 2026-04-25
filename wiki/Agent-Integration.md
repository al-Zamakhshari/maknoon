# AI Agent and Automation Integration
> **Standardized Cryptographic Interface for Autonomous Systems**

## Executive Summary
Maknoon is designed for seamless integration with autonomous systems, Large Language Models (LLMs), and AI agents. By implementing the **Model Context Protocol (MCP)** and providing a self-describing command schema, Maknoon enables agents to perform complex cryptographic operations within a governed, machine-readable environment.

---

## Model Context Protocol (MCP) Integration
Maknoon includes a native MCP server that exposes the engine's capabilities as structured tools. This allows AI assistants (e.g., Claude, Cursor) to interact with the cryptographic layer without manual command construction.

### Available Tools

| Tool | Capability |
| :--- | :--- |
| `inspect_file` | Analyzes header metadata, profile versions, and signature validity. |
| `encrypt_file` | Performs hybrid PQC encryption on local filesystem resources. |
| `decrypt_file` | Restores encrypted assets using managed private identities. |
| `vault_get` / `set` | Secure storage and retrieval of credentials via the authenticated engine. |
| `identity_active` | Enumerates available public keys and cryptographic profiles. |
| `identity_publish` | Provisions and announces identity records to decentralized registries. |

### Configuration Example (Claude Desktop)
To register the Maknoon MCP server, update the `mcpServers` configuration block:

```json
{
  "mcpServers": {
    "maknoon": {
      "command": "maknoon",
      "args": ["mcp", "serve"],
      "env": {
        "MAKNOON_AGENT_MODE": "1"
      }
    }
  }
}
```

---

## Automated Agent Handshake
Maknoon implements an automated detection mechanism to transition into machine-readable (JSON) output modes, ensuring compatibility with automated pipelines.

The engine activates **Agent Mode** when the following condition is met:
*   **Environment Variable**: `MAKNOON_AGENT_MODE=1` is explicitly set.

---

## Sandboxed Container Deployment
For maximum security in production AI environments, Maknoon should be deployed as a containerized sandbox. This provides process-level isolation, preventing an AI agent from accessing any sensitive data outside the explicitly mounted workspace.

### Docker Implementation
Maknoon utilizes a **multi-stage build** starting from an empty `scratch` image, resulting in a minimal (~15MB) container with **zero OS-level attack surface**. Using **Docker Buildx** ensures optimized, multi-platform builds.

```bash
# Build the secure sandbox image using BuildKit (buildx)
docker buildx build -t maknoon-sandbox --load .

# Multi-platform build (AMD64 + ARM64)
docker buildx build --platform linux/amd64,linux/arm64 -t maknoon-sandbox .
```

### Orchestration via Docker Compose
For persistent MCP server deployments, use the provided `docker-compose.yml` to manage environment variables and volume mounts.

```yaml
services:
  maknoon-mcp:
    image: maknoon-sandbox:latest
    environment:
      - MAKNOON_AGENT_MODE=1
      - MAKNOON_PASSPHRASE=${MAKNOON_PASSPHRASE}
    volumes:
      - ./agent-workspace:/home/maknoon
    stdin_open: true
    tty: true
```

---

## Schema-Based Discovery
To facilitate autonomous discovery, Maknoon provides a comprehensive JSON-Schema of its entire command hierarchy.

```bash
# Generate machine-readable command specification
maknoon schema
```

> **Integration Note:** Autonomous agents are encouraged to execute `maknoon schema` during initialization. This allows the agent to dynamically map available flags (e.g., `--stealth`, `--nostr`, `--profile`) to its internal tool definitions without external documentation dependencies.

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

---

## Security and Governance
When operating in Agent Mode, Maknoon enforces a strict security sandbox to prevent unauthorized resource access or policy modification.

*   **Restricted Filesystem**: Agents are limited to specific permitted directories (e.g., project root, system temp).
*   **Immutable Configuration**: Global security policies and identity registries cannot be modified via agent-initiated commands.
*   **Resource Throttling**: Parallel worker counts and Argon2id complexity parameters are clamped to prevent resource exhaustion.

> **Governance Notice:** Organizations should monitor MCP tool usage via the Maknoon audit decorator. All agent-initiated cryptographic operations are logged with structured metadata, ensuring full traceability of automated actions.
