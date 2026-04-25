package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// MCPServerCmd returns the cobra command for launching the native MCP server.
func MCPServerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Start the Model Context Protocol (MCP) server for AI Agent integration",
		Long: `Launches the native Maknoon MCP server. This allows AI agents to interact 
with the engine's cryptographic tools over standard I/O.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			viper.Set("agent_mode", "1")
			if err := InitEngine(); err != nil {
				return fmt.Errorf("failed to initialize engine: %w", err)
			}

			s := createMCPServer()
			if err := server.ServeStdio(s); err != nil {
				return fmt.Errorf("MCP server error: %w", err)
			}
			return nil
		},
	}
}

func createMCPServer() *server.MCPServer {
	s := server.NewMCPServer("Maknoon PQC Server", "1.3.2", server.WithLogging())
	engine := GlobalContext.Engine

	getArgs := func(request mcp.CallToolRequest) map[string]interface{} {
		args, _ := request.Params.Arguments.(map[string]interface{})
		return args
	}

	getString := func(args map[string]any, key string, def string) string {
		if val, ok := args[key].(string); ok {
			return val
		}
		return def
	}

	getBool := func(args map[string]any, key string, def bool) bool {
		if val, ok := args[key].(bool); ok {
			return val
		}
		return def
	}

	// 1. Vault Tools
	s.AddTool(mcp.NewTool("vault_get", mcp.WithDescription("Retrieve a secret from the vault")), 
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			service := getString(args, "service", "")
			vault := getString(args, "vault", "default")
			pass := []byte(viper.GetString("passphrase"))
			entry, err := engine.VaultGet(nil, vault, service, pass, "")
			if err != nil { return formatMCPError(err, "vault_get") }
			if entry == nil { return mcp.NewToolResultError(`{"error":"not found"}`), nil }
			res, _ := json.Marshal(entry)
			crypto.SafeClear(entry.Password)
			return mcp.NewToolResultText(string(res)), nil
		})

	s.AddTool(mcp.NewTool("vault_set", mcp.WithDescription("Store a secret in the vault")), 
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			entry := &crypto.VaultEntry{
				Service: getString(args, "service", ""),
				Username: getString(args, "username", ""),
				Password: []byte(getString(args, "password", "")),
			}
			err := engine.VaultSet(nil, getString(args, "vault", "default"), entry, []byte(viper.GetString("passphrase")), "")
			crypto.SafeClear(entry.Password)
			if err != nil { return formatMCPError(err, "vault_set") }
			return mcp.NewToolResultText(`{"status":"success"}`), nil
		})

	// 2. Crypto Tools
	s.AddTool(mcp.NewTool("encrypt_file", mcp.WithDescription("Encrypt a file")), 
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			opts := crypto.Options{Passphrase: []byte(viper.GetString("passphrase")), ProfileID: 1}
			if pk := getString(args, "public_key", ""); pk != "" {
				m := crypto.NewIdentityManager()
				if res := m.ResolveKeyPath(pk, ""); res != "" {
					data, _ := os.ReadFile(res)
					opts.Recipients = append(opts.Recipients, data)
				}
			}
			in, _ := os.Open(getString(args, "input", ""))
			out, _ := os.Create(getString(args, "output", ""))
			defer out.Close()
			_, err := engine.Protect(nil, "", in, out, opts)
			if err != nil { return formatMCPError(err, "encrypt_file") }
			return mcp.NewToolResultText(`{"status":"success"}`), nil
		})

	s.AddTool(mcp.NewTool("inspect_file", mcp.WithDescription("Analyze header metadata")), 
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			in, _ := os.Open(getString(args, "path", ""))
			info, err := engine.Inspect(nil, in)
			if err != nil { return formatMCPError(err, "inspect_file") }
			res, _ := json.Marshal(info)
			return mcp.NewToolResultText(string(res)), nil
		})

	// 3. P2P & Network Tools
	s.AddTool(mcp.NewTool("p2p_send", mcp.WithDescription("Start a secure P2P file transfer")), 
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			text := getString(args, "text", "")
			path := getString(args, "path", "")
			var r io.Reader
			var name string
			if text != "" {
				r = strings.NewReader(text)
				name = "text-message"
			} else {
				f, _ := os.Open(path)
				r = f
				name = filepath.Base(path)
			}
			opts := crypto.P2PSendOptions{
				Passphrase: []byte(viper.GetString("passphrase")),
				Stealth: getBool(args, "stealth", false),
			}
			code, _, err := engine.P2PSend(nil, name, r, opts)
			if err != nil { return formatMCPError(err, "p2p_send") }
			return mcp.NewToolResultText(fmt.Sprintf(`{"code":"%s","status":"established"}`, code)), nil
		})

	s.AddTool(mcp.NewTool("start_chat", mcp.WithDescription("Initiate a Ghost Chat session")), 
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			session := crypto.NewChatSession("maknoon-mcp")
			code, err := session.StartHost(ctx)
			if err != nil { return formatMCPError(err, "start_chat") }
			session.Close()
			return mcp.NewToolResultText(fmt.Sprintf(`{"status":"established","code":"%s"}`, code)), nil
		})

	// 4. Utility Tools
	s.AddTool(mcp.NewTool("gen_passphrase", mcp.WithDescription("Generate a secure mnemonic")), 
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			words, _ := args["words"].(float64)
			pass, err := engine.GeneratePassphrase(nil, int(words), "-")
			if err != nil { return formatMCPError(err, "gen_passphrase") }
			return mcp.NewToolResultText(pass), nil
		})

	return s
}

func formatMCPError(err error, tool string) (*mcp.CallToolResult, error) {
	resp := map[string]interface{}{"error": err.Error(), "tool": tool}
	var policyErr *crypto.ErrPolicyViolation
	if crypto.As(err, &policyErr) {
		resp["type"] = "security_policy_violation"
		resp["is_security_violation"] = true
	}
	raw, _ := json.Marshal(resp)
	return mcp.NewToolResultError(string(raw)), nil
}
