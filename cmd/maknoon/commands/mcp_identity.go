package commands

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"
)

func registerIdentityTools(s *server.MCPServer, engine crypto.MaknoonEngine) {
	s.AddTool(mcp.NewTool("identity_list", mcp.WithDescription("List all active identities")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			list, err := engine.IdentityActive(&crypto.EngineContext{Context: ctx})
			if err != nil {
				return crypto.FormatMCPError(err, "identity_list")
			}
			res, _ := json.Marshal(list)
			return mcp.NewToolResultText(string(res)), nil
		})

	s.AddTool(mcp.NewTool("identity_keygen", mcp.WithDescription("Generate a new Post-Quantum (KEM & SIG) identity")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			output := getString(args, "output", "")
			pass := viper.GetString("passphrase")
			profile := getString(args, "profile", "nist")

			res, err := engine.CreateIdentity(&crypto.EngineContext{Context: ctx}, output, []byte(pass), "", false, profile)
			if err != nil {
				return crypto.FormatMCPError(err, "identity_keygen")
			}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("identity_info", mcp.WithDescription("Get detailed information about an identity")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			name := getString(args, "name", "")
			res, err := engine.IdentityInfo(&crypto.EngineContext{Context: ctx}, name)
			if err != nil {
				return crypto.FormatMCPError(err, "identity_info")
			}
			raw, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(raw)), nil
		})

	s.AddTool(mcp.NewTool("identity_rename", mcp.WithDescription("Rename an identity")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			oldName := getString(args, "old_name", "")
			newName := getString(args, "new_name", "")
			err := engine.IdentityRename(&crypto.EngineContext{Context: ctx}, oldName, newName)
			if err != nil {
				return crypto.FormatMCPError(err, "identity_rename")
			}
			res := crypto.IdentityResult{Status: "success", From: oldName, To: newName}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("identity_split", mcp.WithDescription("Split an identity into mnemonic shards (Shamir's Secret Sharing)")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			name := getString(args, "name", "")
			threshold, _ := args["threshold"].(float64)
			shares, _ := args["shares"].(float64)
			if threshold == 0 {
				threshold = 2
			}
			if shares == 0 {
				shares = 3
			}

			pass := viper.GetString("passphrase")
			shards, err := engine.IdentitySplit(&crypto.EngineContext{Context: ctx}, name, int(threshold), int(shares), pass)
			if err != nil {
				return crypto.FormatMCPError(err, "identity_split")
			}
			res := crypto.IdentityResult{Status: "success", Identity: name, Shares: shards}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("identity_combine", mcp.WithDescription("Combine mnemonic shards to recover an identity")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			output := getString(args, "output", "")
			pass := viper.GetString("passphrase")
			noPassword, _ := args["no_password"].(bool)

			var shards []string
			if rawShards, ok := args["shares"].([]any); ok {
				for _, s := range rawShards {
					if str, ok := s.(string); ok {
						shards = append(shards, str)
					}
				}
			}

			path, err := engine.IdentityCombine(&crypto.EngineContext{Context: ctx}, shards, output, pass, noPassword)
			if err != nil {
				return crypto.FormatMCPError(err, "identity_combine")
			}
			res := crypto.IdentityResult{Status: "success", Identity: output, BasePath: path}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("identity_publish", mcp.WithDescription("Publish identity to a registry (DNS or Nostr)")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			handle := getString(args, "handle", "")
			registry := getString(args, "registry", "nostr")
			local, _ := args["local"].(bool)

			opts := crypto.IdentityPublishOptions{
				Name:       getString(args, "name", ""),
				Passphrase: viper.GetString("passphrase"),
				Local:      local,
			}

			if registry == "nostr" {
				opts.Nostr = true
			} else if registry == "dns" {
				opts.DNS = true
			}

			err := engine.IdentityPublish(&crypto.EngineContext{Context: ctx}, handle, opts)
			if err != nil {
				return crypto.FormatMCPError(err, "identity_publish")
			}
			res := crypto.IdentityResult{Status: "success", Handle: handle}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("contact_list", mcp.WithDescription("List all trusted contacts")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			list, err := engine.ContactList(&crypto.EngineContext{Context: ctx})
			if err != nil {
				return crypto.FormatMCPError(err, "contact_list")
			}
			res, _ := json.Marshal(list)
			return mcp.NewToolResultText(string(res)), nil
		})

	s.AddTool(mcp.NewTool("contact_add", mcp.WithDescription("Add a new trusted contact")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			petname := getString(args, "petname", "")
			kemPub := getString(args, "kem_pub", "")
			sigPub := getString(args, "sig_pub", "")
			note := getString(args, "note", "")

			err := engine.ContactAdd(&crypto.EngineContext{Context: ctx}, petname, kemPub, sigPub, note)
			if err != nil {
				return crypto.FormatMCPError(err, "contact_add")
			}
			res := crypto.CommonResult{Status: "success"}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("contact_delete", mcp.WithDescription("Remove a trusted contact")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			petname := getString(args, "petname", "")
			err := engine.ContactDelete(&crypto.EngineContext{Context: ctx}, petname)
			if err != nil {
				return crypto.FormatMCPError(err, "contact_delete")
			}
			res := crypto.CommonResult{Status: "success"}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("resolve_identity", mcp.WithDescription("Resolve a petname or key path to a raw public key")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			input := getString(args, "input", "")
			pk, err := engine.ResolvePublicKey(&crypto.EngineContext{Context: ctx}, input, false)
			if err != nil {
				return crypto.FormatMCPError(err, "resolve_identity")
			}
			res := crypto.ResolveResult{PublicKey: hex.EncodeToString(pk)}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})
}
