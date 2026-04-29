package commands

import (
	"context"
	"encoding/json"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"
)

func registerVaultTools(s *server.MCPServer, engine crypto.MaknoonEngine) {
	s.AddTool(mcp.NewTool("vault_get", mcp.WithDescription("Retrieve a secret from the vault")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			service := getString(args, "service", "")
			vault := getString(args, "vault", "default")
			pass := []byte(viper.GetString("passphrase"))
			entry, err := engine.VaultGet(nil, vault, service, pass, "")
			if err != nil {
				return crypto.FormatMCPError(err, "vault_get")
			}
			if entry == nil {
				return mcp.NewToolResultError(`{"error":"not found"}`), nil
			}
			res, _ := json.Marshal(entry)
			crypto.SafeClear(entry.Password)
			return mcp.NewToolResultText(string(res)), nil
		})

	s.AddTool(mcp.NewTool("vault_set", mcp.WithDescription("Store a secret in the vault")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			entry := &crypto.VaultEntry{
				Service:  getString(args, "service", ""),
				Username: getString(args, "username", ""),
				Password: []byte(getString(args, "password", "")),
			}
			err := engine.VaultSet(nil, getString(args, "vault", "default"), entry, []byte(viper.GetString("passphrase")), "")
			crypto.SafeClear(entry.Password)
			if err != nil {
				return crypto.FormatMCPError(err, "vault_set")
			}
			return mcp.NewToolResultText(`{"status":"success"}`), nil
		})
}

func getArgs(request mcp.CallToolRequest) map[string]interface{} {
	args, _ := request.Params.Arguments.(map[string]interface{})
	return args
}

func getString(args map[string]any, key string, def string) string {
	if val, ok := args[key].(string); ok {
		return val
	}
	return def
}

func getBool(args map[string]any, key string, def bool) bool {
	if val, ok := args[key].(bool); ok {
		return val
	}
	return def
}
