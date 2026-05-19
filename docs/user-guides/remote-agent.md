# Remote Agent Integration — MCP SSE Server and `call` Client

## Overview

Maknoon exposes all its cryptographic tools over the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). This enables AI agents (Claude Desktop, Cursor, custom agents) to encrypt files, manage vaults, resolve identities, and more — without the agent having access to raw keys.

Two commands support this workflow:
- **`maknoon mcp`** — the MCP server (stdio or SSE transport)
- **`maknoon call`** — a CLI MCP client for calling tools on a running server

---

## Starting the MCP Server

### stdio mode (Claude Desktop / Cursor)

The simplest integration: the MCP client spawns `maknoon mcp` as a subprocess. No network, no TLS required.

```bash
maknoon mcp --transport stdio
```

**Claude Desktop config** (`~/.config/claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "maknoon": {
      "command": "maknoon",
      "args": ["mcp", "--transport", "stdio"],
      "env": {
        "MAKNOON_PASSPHRASE": "my-vault-passphrase"
      }
    }
  }
}
```

### SSE mode (remote agents, Kubernetes, CI pipelines)

For agents running in a different process or machine. TLS is mandatory — Maknoon rejects SSE connections without a certificate.

```bash
maknoon mcp \
  --transport sse \
  --address :8080 \
  --tls-cert /path/to/cert.pem \
  --tls-key /path/to/key.pem
```

The server uses Post-Quantum TLS 1.3 with `X25519MLKEM768` key exchange automatically. No configuration needed to enable PQC.

#### With a governance policy file

```bash
maknoon mcp --transport sse --tls-cert cert.pem --tls-key key.pem \
  --policy /etc/maknoon/governance.json
```

The policy gates agent operations (e.g., requiring signed approval for vault access). See `config set gov.require_signed true` to enforce.

---

## Calling Tools from the CLI — `maknoon call`

`call` is an MCP client that invokes a single tool on a running Maknoon SSE server and prints the result as JSON. Useful for shell scripting and CI automation.

### Basic syntax

```bash
maknoon call <tool_name> --addr <host:port> --args '<json>'
```

### Examples

**Encrypt a file:**
```bash
maknoon call encrypt_file \
  --addr localhost:8080 \
  --args '{"input": "/tmp/report.pdf", "output": "/tmp/report.pdf.makn"}'
```

**Retrieve a vault secret:**
```bash
maknoon call vault_get \
  --addr localhost:8080 \
  --args '{"service": "prod-db", "vault": "default"}'
```

**Generate a passphrase:**
```bash
maknoon call gen_passphrase --addr localhost:8080 --args '{"words": 6}'
```

**Multi-recipient encryption:**
```bash
maknoon call encrypt_file \
  --addr localhost:8080 \
  --args '{"input":"secret.txt","output":"secret.txt.makn","public_keys":"@alice,@bob"}'
```

### Local dev with self-signed certificates

```bash
maknoon call encrypt_file --addr localhost:8080 --insecure \
  --args '{"input":"test.txt","output":"test.txt.makn"}'
```

`--insecure` skips TLS certificate verification. **Never use in production.**

---

## PQC Transport

The `call` command and the SSE server both prefer `X25519MLKEM768` (ML-KEM-768 + X25519 hybrid) for TLS key exchange. This protects orchestration traffic against "harvest now, decrypt later" attacks — traffic captured today cannot be decrypted by a future quantum computer.

No configuration is needed; PQC is the default.

---

## Shell Scripting Pattern

```bash
#!/bin/bash
SERVER="localhost:8080"

# Derive a session key once
KEY=$(maknoon session derive -s "$VAULT_PASS")

# Encrypt all PDFs
for f in reports/*.pdf; do
  maknoon call encrypt_file --addr "$SERVER" \
    --args "{\"input\":\"$f\",\"output\":\"${f}.makn\"}"
done

# Store a secret
maknoon call vault_set --addr "$SERVER" \
  --args '{"service":"deploy-key","username":"ci","password":"'$DEPLOY_KEY'"}'
```

---

## Available Tools

All 45 MCP tools are documented in [`docs/integration/TOOL-REFERENCE.json`](../integration/TOOL-REFERENCE.json) and [`docs/integration/mcp-server.md`](../integration/mcp-server.md).

**Tool categories:**
| Category | Tools |
|----------|-------|
| Crypto | `encrypt_file`, `decrypt_file`, `sign_file`, `verify_file`, `inspect_file`, `reencrypt_file`, `shred_file`, `gen_passphrase`, `gen_password` |
| Vault | `vault_get`, `vault_set`, `vault_list`, `vault_status`, `vault_check_shards`, `vault_set_blob`, `vault_get_blob`, and more |
| Identity | `identity_keygen`, `identity_publish`, `resolve_identity`, `contact_add`, `aggregate_signatures`, and more |
| Dispersal | `fragment_file`, `reassemble_file` |
| Config | `config_list`, `config_update`, `diagnostic`, `audit_export`, `audit_verify` |
