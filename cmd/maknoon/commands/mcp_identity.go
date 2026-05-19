package commands

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"
)

func registerIdentityTools(s *server.MCPServer, engine crypto.MaknoonEngine) {
	s.AddTool(mcp.NewTool("identity_list",
		mcp.WithDescription("List all local identities"),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		list, err := engine.IdentityActive(&crypto.EngineContext{Context: ctx})
		if err != nil {
			return crypto.FormatMCPError(err, "identity_list")
		}
		res, _ := json.Marshal(list)
		return mcp.NewToolResultText(string(res)), nil
	})

	s.AddTool(mcp.NewTool("identity_keygen",
		mcp.WithDescription("Generate a new Post-Quantum (KEM + SIG) identity keypair"),
		mcp.WithString("output", mcp.Description("Base path for key files (default: ~/.maknoon/keys/<name>)")),
		mcp.WithString("profile", mcp.Description("Cryptographic profile: nist (ML-KEM+ML-DSA) or conservative (FrodoKEM+SLH-DSA)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	s.AddTool(mcp.NewTool("identity_info",
		mcp.WithDescription("Get detailed information about a local identity"),
		mcp.WithString("name", mcp.Required(), mcp.Description("Identity name or key path")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		name := getString(args, "name", "")
		res, err := engine.IdentityInfo(&crypto.EngineContext{Context: ctx}, name)
		if err != nil {
			return crypto.FormatMCPError(err, "identity_info")
		}
		raw, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(raw)), nil
	})

	s.AddTool(mcp.NewTool("identity_rename",
		mcp.WithDescription("Rename a local identity"),
		mcp.WithString("old_name", mcp.Required(), mcp.Description("Current identity name")),
		mcp.WithString("new_name", mcp.Required(), mcp.Description("New identity name")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	s.AddTool(mcp.NewTool("identity_delete",
		mcp.WithDescription("Permanently delete a local identity and securely shred its private keys"),
		mcp.WithString("name", mcp.Required(), mcp.Description("Identity name to delete")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		name := getString(args, "name", "")
		err := engine.IdentityDelete(&crypto.EngineContext{Context: ctx}, name)
		if err != nil {
			return crypto.FormatMCPError(err, "identity_delete")
		}
		res := crypto.IdentityResult{Status: "success", Identity: name}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("identity_split",
		mcp.WithDescription("Split an identity private key into mnemonic shards using Shamir's Secret Sharing"),
		mcp.WithString("name", mcp.Required(), mcp.Description("Identity name to split")),
		mcp.WithNumber("threshold", mcp.Description("Minimum shards required to recover (default: 2)")),
		mcp.WithNumber("shares", mcp.Description("Total number of shards to generate (default: 3)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		name := getString(args, "name", "")
		threshold := getInt(args, "threshold", 2)
		shares := getInt(args, "shares", 3)
		pass := viper.GetString("passphrase")
		shards, err := engine.IdentitySplit(&crypto.EngineContext{Context: ctx}, name, threshold, shares, pass)
		if err != nil {
			return crypto.FormatMCPError(err, "identity_split")
		}
		res := crypto.IdentityResult{Status: "success", Identity: name, Shares: shards}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("identity_combine",
		mcp.WithDescription("Recover an identity from mnemonic shards"),
		mcp.WithString("shares", mcp.Required(), mcp.Description("JSON array of mnemonic shard strings")),
		mcp.WithString("output", mcp.Required(), mcp.Description("Base path for recovered key files")),
		mcp.WithBoolean("no_password", mcp.Description("Skip passphrase protection on recovered key (default: false)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		output := getString(args, "output", "")
		pass := viper.GetString("passphrase")
		noPassword := getBool(args, "no_password", false)
		shards := getStringSlice(args, "shares")

		path, err := engine.IdentityCombine(&crypto.EngineContext{Context: ctx}, shards, output, pass, noPassword)
		if err != nil {
			return crypto.FormatMCPError(err, "identity_combine")
		}
		res := crypto.IdentityResult{Status: "success", Identity: output, BasePath: path}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("identity_publish",
		mcp.WithDescription("Publish an identity to a registry (nostr, wkd, or dns)"),
		mcp.WithString("handle", mcp.Required(), mcp.Description("Public handle to publish (e.g. @alice or @alice@example.com)")),
		mcp.WithString("name", mcp.Description("Local identity name (uses default identity if omitted)")),
		mcp.WithString("registry", mcp.Description("Registry: nostr (default), wkd (HTTPS static file, requires alice@domain handle), dns")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		handle := getString(args, "handle", "")
		registry := getString(args, "registry", "nostr")

		opts := crypto.IdentityPublishOptions{
			Name:       getString(args, "name", ""),
			Passphrase: viper.GetString("passphrase"),
		}
		switch registry {
		case "wkd":
			opts.WKD = true
		case "dns":
			opts.DNS = true
		default:
			opts.Nostr = true
		}

		err := engine.IdentityPublish(&crypto.EngineContext{Context: ctx}, handle, opts)

		// WKD returns a manual-step result, not an error.
		var wkdManual *crypto.ErrWKDPublishManual
		if errors.As(err, &wkdManual) {
			res := map[string]any{
				"status":  "action_required",
				"handle":  handle,
				"url":     wkdManual.URL,
				"content": string(wkdManual.Content),
			}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		}
		if err != nil {
			return crypto.FormatMCPError(err, "identity_publish")
		}
		res := crypto.IdentityResult{Status: "success", Handle: handle}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("contact_list",
		mcp.WithDescription("List all trusted contacts"),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		list, err := engine.ContactList(&crypto.EngineContext{Context: ctx})
		if err != nil {
			return crypto.FormatMCPError(err, "contact_list")
		}
		res, _ := json.Marshal(list)
		return mcp.NewToolResultText(string(res)), nil
	})

	s.AddTool(mcp.NewTool("contact_add",
		mcp.WithDescription("Add a trusted contact with their public keys"),
		mcp.WithString("petname", mcp.Required(), mcp.Description("Local nickname for this contact")),
		mcp.WithString("kem_pub", mcp.Required(), mcp.Description("Contact's KEM public key (hex or file path)")),
		mcp.WithString("sig_pub", mcp.Required(), mcp.Description("Contact's signature public key (hex or file path)")),
		mcp.WithString("note", mcp.Description("Optional note about this contact")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	s.AddTool(mcp.NewTool("contact_delete",
		mcp.WithDescription("Remove a trusted contact"),
		mcp.WithString("petname", mcp.Required(), mcp.Description("Petname of the contact to remove")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	s.AddTool(mcp.NewTool("resolve_identity",
		mcp.WithDescription("Resolve a petname, key path, or @nostr handle to a raw public key"),
		mcp.WithString("input", mcp.Required(), mcp.Description("Petname, file path, or @handle to resolve")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	s.AddTool(mcp.NewTool("aggregate_signatures",
		mcp.WithDescription("Combine multiple independent ML-DSA signatures into a threshold signature"),
		mcp.WithString("signatures", mcp.Required(), mcp.Description("JSON array of .sig file paths to aggregate")),
		mcp.WithString("output", mcp.Description("Output path for the aggregated signature (default: multi.sig)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		sigPaths := getStringSlice(args, "signatures")
		output := getString(args, "output", "multi.sig")

		var sigs [][]byte
		for _, p := range sigPaths {
			sig, err := os.ReadFile(p)
			if err != nil {
				return crypto.FormatMCPError(err, "aggregate_signatures")
			}
			sigs = append(sigs, sig)
		}

		agg, err := engine.Aggregate(&crypto.EngineContext{Context: ctx}, sigs)
		if err != nil {
			return crypto.FormatMCPError(err, "aggregate_signatures")
		}
		if err := os.WriteFile(output, agg, 0600); err != nil {
			return crypto.FormatMCPError(err, "aggregate_signatures")
		}

		res := crypto.SignResult{Status: "success", SignaturePath: output}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})
}
