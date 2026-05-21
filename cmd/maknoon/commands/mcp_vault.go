package commands

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"
)

func registerVaultTools(s *server.MCPServer, engine crypto.MaknoonEngine) {
	s.AddTool(mcp.NewTool("vault_init_institutional",
		mcp.WithDescription("Initialize a new institutional vault governed by a quorum of peers"),
		mcp.WithString("name", mcp.Required(), mcp.Description("Vault name")),
		mcp.WithNumber("threshold", mcp.Description("Minimum shares required to unlock (default: 2)")),
		mcp.WithNumber("shares", mcp.Description("Total number of key shares to generate (default: 3)")),
		mcp.WithString("peers", mcp.Description("Comma-separated list of peer identity names or IDs")),
		mcp.WithString("passphrase", mcp.Description("Initial vault passphrase (use server passphrase if omitted)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		name := getString(args, "name", "")
		threshold := getInt(args, "threshold", 2)
		shares := getInt(args, "shares", 3)

		passRaw := getString(args, "passphrase", viper.GetString("passphrase"))
		pass := crypto.SecretBytes(passRaw)
		defer crypto.SafeClear(pass)

		peers := getStringSlice(args, "peers")
		if peerStr := getString(args, "peers", ""); len(peers) == 0 && peerStr != "" {
			for _, p := range strings.Split(peerStr, ",") {
				if t := strings.TrimSpace(p); t != "" {
					peers = append(peers, t)
				}
			}
		}

		res, err := engine.VaultInitInstitutional(&crypto.EngineContext{Context: ctx}, name, threshold, shares, peers, pass)
		if err != nil {
			return crypto.FormatMCPError(err, "vault_init_institutional")
		}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("vault_unlock",
		mcp.WithDescription("Derive the vault key once and cache it for the session TTL (default 5 min). Subsequent vault_get/vault_set/vault_list calls skip Argon2id entirely — use this before any bulk vault operation."),
		mcp.WithString("vault", mcp.Description("Vault name (default: default)")),
		mcp.WithNumber("ttl_seconds", mcp.Description("Session lifetime in seconds (default: 300)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		vault := getString(args, "vault", "default")
		ttl := getInt(args, "ttl_seconds", 0)
		pass := crypto.SecretBytes(viper.GetString("passphrase"))
		if err := engine.VaultUnlock(&crypto.EngineContext{Context: ctx}, vault, pass, ttl); err != nil {
			return crypto.FormatMCPError(err, "vault_unlock")
		}
		out, _ := json.Marshal(map[string]any{"status": "unlocked", "vault": vault, "ttl_seconds": ttl})
		return mcp.NewToolResultText(string(out)), nil
	})

	s.AddTool(mcp.NewTool("vault_lock",
		mcp.WithDescription("Immediately wipe the cached session key for the named vault."),
		mcp.WithString("vault", mcp.Description("Vault name (default: default)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		vault := getString(getArgs(request), "vault", "default")
		if err := engine.VaultLock(&crypto.EngineContext{Context: ctx}, vault); err != nil {
			return crypto.FormatMCPError(err, "vault_lock")
		}
		out, _ := json.Marshal(map[string]any{"status": "locked", "vault": vault})
		return mcp.NewToolResultText(string(out)), nil
	})

	s.AddTool(mcp.NewTool("vault_get",
		mcp.WithDescription("Retrieve a secret from the vault. Each call runs Argon2id KDF (~60 ms) unless vault_unlock was called first."),
		mcp.WithString("service", mcp.Required(), mcp.Description("Service or key name to retrieve")),
		mcp.WithString("vault", mcp.Description("Vault name (default: default)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		service := getString(args, "service", "")
		vault := getString(args, "vault", "default")
		pass := crypto.SecretBytes(viper.GetString("passphrase"))
		entry, err := engine.VaultGet(&crypto.EngineContext{Context: ctx}, vault, service, pass, "")
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

	s.AddTool(mcp.NewTool("vault_set",
		mcp.WithDescription("Store a secret in the vault"),
		mcp.WithString("service", mcp.Required(), mcp.Description("Service or key name")),
		mcp.WithString("username", mcp.Description("Username associated with the credential")),
		mcp.WithString("password", mcp.Description("Secret value to store")),
		mcp.WithString("vault", mcp.Description("Vault name (default: default)")),
		mcp.WithBoolean("overwrite", mcp.Description("Overwrite existing entry if present (default: false)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		entry := &crypto.VaultEntry{
			Service:  getString(args, "service", ""),
			Username: getString(args, "username", ""),
			Password: crypto.SecretBytes(getString(args, "password", "")),
		}
		overwrite := getBool(args, "overwrite", false)
		err := engine.VaultSet(&crypto.EngineContext{Context: ctx}, getString(args, "vault", "default"), entry, crypto.SecretBytes(viper.GetString("passphrase")), "", overwrite)
		crypto.SafeClear(entry.Password)
		if err != nil {
			return crypto.FormatMCPError(err, "vault_set")
		}
		res := crypto.VaultResult{Status: "success", Service: entry.Service}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("vault_list",
		mcp.WithDescription("List all entries in a vault"),
		mcp.WithString("vault", mcp.Description("Vault name (default: default)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	s.AddTool(mcp.NewTool("vault_delete",
		mcp.WithDescription("Delete a vault or a specific service entry"),
		mcp.WithString("name", mcp.Required(), mcp.Description("Vault name or path to delete")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	s.AddTool(mcp.NewTool("vault_rename",
		mcp.WithDescription("Rename a vault"),
		mcp.WithString("old_name", mcp.Required(), mcp.Description("Current vault name")),
		mcp.WithString("new_name", mcp.Required(), mcp.Description("New vault name")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	s.AddTool(mcp.NewTool("vault_set_blob",
		mcp.WithDescription("Store arbitrary encrypted data as agent memory"),
		mcp.WithString("key", mcp.Required(), mcp.Description("Key name for the blob")),
		mcp.WithString("data", mcp.Required(), mcp.Description("Data to store (encrypted at rest)")),
		mcp.WithString("vault", mcp.Description("Vault name (default: agent_memory)")),
		mcp.WithBoolean("overwrite", mcp.Description("Overwrite existing entry (default: false)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		entry := &crypto.VaultEntry{
			Service:  getString(args, "key", ""),
			Blob:     crypto.SecretBytes(getString(args, "data", "")),
			Username: "agent_memory",
		}
		overwrite := getBool(args, "overwrite", false)
		vault := getString(args, "vault", "agent_memory")
		pass := crypto.SecretBytes(viper.GetString("passphrase"))

		err := engine.VaultSet(&crypto.EngineContext{Context: ctx}, vault, entry, pass, "", overwrite)
		crypto.SafeClear(entry.Blob)
		if err != nil {
			return crypto.FormatMCPError(err, "vault_set_blob")
		}
		res := crypto.VaultResult{Status: "success", Service: entry.Service, Vault: vault}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("vault_get_blob",
		mcp.WithDescription("Retrieve arbitrary encrypted data (agent memory)"),
		mcp.WithString("key", mcp.Required(), mcp.Description("Key name of the blob to retrieve")),
		mcp.WithString("vault", mcp.Description("Vault name (default: agent_memory)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		key := getString(args, "key", "")
		vault := getString(args, "vault", "agent_memory")
		pass := crypto.SecretBytes(viper.GetString("passphrase"))

		entry, err := engine.VaultGet(&crypto.EngineContext{Context: ctx}, vault, key, pass, "")
		if err != nil {
			return crypto.FormatMCPError(err, "vault_get_blob")
		}
		if entry == nil {
			return mcp.NewToolResultError(`{"error":"not found"}`), nil
		}
		res := map[string]string{"status": "success", "key": key, "data": string(entry.Blob)}
		crypto.SafeClear(entry.Blob)
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("vault_split",
		mcp.WithDescription("Split a vault master key into mnemonic recovery shards (Shamir's Secret Sharing)"),
		mcp.WithString("vault", mcp.Required(), mcp.Description("Vault name to split")),
		mcp.WithNumber("threshold", mcp.Description("Minimum shards required for recovery (default: 2)")),
		mcp.WithNumber("shares", mcp.Description("Total number of shards to generate (default: 3)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		vault := getString(args, "vault", "default")
		threshold := getInt(args, "threshold", 2)
		shares := getInt(args, "shares", 3)
		pass := viper.GetString("passphrase")
		shards, err := engine.VaultSplit(&crypto.EngineContext{Context: ctx}, vault, threshold, shares, pass)
		if err != nil {
			return crypto.FormatMCPError(err, "vault_split")
		}
		res := crypto.VaultResult{Status: "success", Vault: vault, Shares: shards}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("vault_recover",
		mcp.WithDescription("Recover a vault from mnemonic shards"),
		mcp.WithString("vault", mcp.Required(), mcp.Description("Target vault name")),
		mcp.WithString("output", mcp.Description("Output path for recovered vault file")),
		mcp.WithString("shares", mcp.Required(), mcp.Description("JSON array of mnemonic shard strings")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		vault := getString(args, "vault", "default")
		output := getString(args, "output", "")
		pass := viper.GetString("passphrase")
		shards := getStringSlice(args, "shares")

		path, err := engine.VaultRecover(&crypto.EngineContext{Context: ctx}, shards, vault, output, pass)
		if err != nil {
			return crypto.FormatMCPError(err, "vault_recover")
		}
		res := crypto.VaultResult{Status: "success", Vault: vault, Output: path}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("vault_status",
		mcp.WithDescription("Check vault health, quorum readiness, and institutional configuration"),
		mcp.WithString("name", mcp.Required(), mcp.Description("Vault name to inspect")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		name := getString(args, "name", "")
		res, err := engine.VaultStatus(&crypto.EngineContext{Context: ctx}, name)
		if err != nil {
			return crypto.FormatMCPError(err, "vault_status")
		}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("vault_check_shards",
		mcp.WithDescription("Validate mnemonic shards before attempting vault recovery"),
		mcp.WithString("shares", mcp.Required(), mcp.Description("JSON array of mnemonic shard strings to validate")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		shards := getStringSlice(args, "shares")
		res, err := engine.VaultCheckShards(&crypto.EngineContext{Context: ctx}, shards)
		if err != nil {
			return crypto.FormatMCPError(err, "vault_check_shards")
		}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})
}
