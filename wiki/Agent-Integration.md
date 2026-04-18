# AI Agent Integration

Maknoon is a first-class citizen for AI agents and LLM-based assistants. It follows the **Model Context Protocol (MCP)** and provides native automated discovery.

## 🤖 Agent Handshake
Maknoon automatically switches to JSON mode if:
1.  The `MAKNOON_AGENT_MODE=1` environment variable is set.
2.  The output is not a TTY (piped or redirected).

This allows agents to use Maknoon without being configured with the `--json` flag explicitly.

## 🔌 MCP Server
Maknoon includes a native Go-based MCP server in `integrations/mcp`. This server allows agents to:
*   `identity_active`: Discover local keys.
*   `vault_get` / `vault_set`: Manage credentials.
*   `encrypt_file`: Protect data.

### How to use with Claude Desktop
Add the following to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "maknoon": {
      "command": "/path/to/maknoon-repo/mcp-server",
      "env": {
        "MAKNOON_BINARY": "/path/to/maknoon-repo/maknoon"
      }
    }
  }
}
```

## 🛠 Automation Variables
*   `MAKNOON_PASSPHRASE`: Non-interactive master key for vault operations.
*   `MAKNOON_PASSWORD`: Non-interactive secret for `vault set`.
*   `MAKNOON_PRIVATE_KEY`: Default path to private identity.
