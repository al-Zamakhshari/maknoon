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
			pass := crypto.SecretBytes(viper.GetString("passphrase"))
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
				Password: crypto.SecretBytes(getString(args, "password", "")),
			}
			overwrite, _ := args["overwrite"].(bool)
			err := engine.VaultSet(nil, getString(args, "vault", "default"), entry, crypto.SecretBytes(viper.GetString("passphrase")), "", overwrite)
			crypto.SafeClear(entry.Password)
			if err != nil {
				return crypto.FormatMCPError(err, "vault_set")
			}
			res := crypto.VaultResult{Status: "success", Service: entry.Service}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("vault_list", mcp.WithDescription("List all entries in a vault")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			vault := getString(args, "vault", "default")
			pass := crypto.SecretBytes(viper.GetString("passphrase"))
			entries, err := engine.VaultList(&crypto.EngineContext{Context: ctx}, vault, pass)
			if err != nil {
				return crypto.FormatMCPError(err, "vault_list")
			}
			res := crypto.VaultResult{Status: "success", Vault: vault, Entries: entries}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("vault_delete", mcp.WithDescription("Delete a vault or a specific service entry")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			name := getString(args, "name", "")
			err := engine.VaultDelete(&crypto.EngineContext{Context: ctx}, name)
			if err != nil {
				return crypto.FormatMCPError(err, "vault_delete")
			}
			res := crypto.VaultResult{Status: "success", Deleted: name}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("vault_rename", mcp.WithDescription("Rename a vault")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			oldName := getString(args, "old_name", "")
			newName := getString(args, "new_name", "")
			err := engine.VaultRename(&crypto.EngineContext{Context: ctx}, oldName, newName)
			if err != nil {
				return crypto.FormatMCPError(err, "vault_rename")
			}
			res := crypto.VaultResult{Status: "success", From: oldName, To: newName}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("vault_split", mcp.WithDescription("Split a vault master key into mnemonic shards")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			vault := getString(args, "vault", "default")
			threshold, _ := args["threshold"].(float64)
			shares, _ := args["shares"].(float64)
			if threshold == 0 {
				threshold = 2
			}
			if shares == 0 {
				shares = 3
			}

			pass := viper.GetString("passphrase")
			shards, err := engine.VaultSplit(&crypto.EngineContext{Context: ctx}, vault, int(threshold), int(shares), pass)
			if err != nil {
				return crypto.FormatMCPError(err, "vault_split")
			}
			res := crypto.VaultResult{Status: "success", Vault: vault, Shares: shards}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("vault_recover", mcp.WithDescription("Recover a vault using mnemonic shards")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			vault := getString(args, "vault", "default")
			output := getString(args, "output", "")
			pass := viper.GetString("passphrase")

			var shards []string
			if rawShards, ok := args["shares"].([]any); ok {
				for _, s := range rawShards {
					if str, ok := s.(string); ok {
						shards = append(shards, str)
					}
				}
			}

			path, err := engine.VaultRecover(&crypto.EngineContext{Context: ctx}, shards, vault, output, pass)
			if err != nil {
				return crypto.FormatMCPError(err, "vault_recover")
			}
			res := crypto.VaultResult{Status: "success", Vault: vault, Output: path}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
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
