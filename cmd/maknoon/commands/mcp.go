package commands

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// MCPServerCmd returns the cobra command for launching the native MCP server.
func MCPServerCmd() *cobra.Command {
	var transport string
	var addr string
	var certFile, keyFile string

	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start the Model Context Protocol (MCP) server for AI Agent integration",
		Long: `Launches the native Maknoon MCP server. This allows AI agents to interact 
with the engine's cryptographic tools over standard I/O (stdio) or HTTP (sse).

For SSE mode, the server uses Go 1.23's native Post-Quantum TLS 1.3 capabilities 
(ML-KEM hybrid) to ensure a quantum-resistant transport handshake.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Bind flags to viper for consistency
			_ = viper.BindPFlag("mcp.transport", cmd.Flags().Lookup("transport"))
			_ = viper.BindPFlag("mcp.address", cmd.Flags().Lookup("address"))
			_ = viper.BindPFlag("mcp.tls_cert", cmd.Flags().Lookup("tls-cert"))
			_ = viper.BindPFlag("mcp.tls_key", cmd.Flags().Lookup("tls-key"))

			// Ensure engine is initialized with AgentPolicy
			viper.Set("agent_mode", "1")
			if err := InitEngine(); err != nil {
				return fmt.Errorf("failed to initialize engine: %w", err)
			}

			s := createMCPServer()

			mode := viper.GetString("mcp.transport")
			switch strings.ToLower(mode) {
			case "stdio":
				if err := server.ServeStdio(s); err != nil {
					return fmt.Errorf("MCP stdio server error: %w", err)
				}
			case "sse":
				return runSSEServer(s)
			default:
				return fmt.Errorf("unsupported transport mode: %s (use stdio or sse)", mode)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&transport, "transport", "stdio", "Transport mode (stdio, sse)")
	cmd.Flags().StringVar(&addr, "address", ":8080", "Address to listen on for SSE mode")
	cmd.Flags().StringVar(&certFile, "tls-cert", "", "Path to TLS certificate for SSE HTTPS")
	cmd.Flags().StringVar(&keyFile, "tls-key", "", "Path to TLS private key for SSE HTTPS")

	return cmd
}

func runSSEServer(s *server.MCPServer) error {
	addr := viper.GetString("mcp.address")
	certFile := viper.GetString("mcp.tls_cert")
	keyFile := viper.GetString("mcp.tls_key")

	sseServer := server.NewSSEServer(s, server.WithBaseURL("https://"+addr))

	// Define the HTTP server with Post-Quantum TLS 1.3 configuration
	httpServer := &http.Server{
		Addr: addr,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			// Prioritize ML-KEM hybrid key exchange (Go 1.23+)
			CurvePreferences: []tls.CurveID{
				tls.X25519MLKEM768, // Post-Quantum Hybrid
				tls.X25519,
				tls.CurveP256,
			},
		},
		Handler: sseServer,
	}

	fmt.Printf("🚀 Starting Post-Quantum Secure MCP SSE Server on %s\n", addr)
	if certFile != "" && keyFile != "" {
		fmt.Println("🔒 Transport encryption active (PQ-TLS 1.3)")
		return httpServer.ListenAndServeTLS(certFile, keyFile)
	}

	fmt.Println("⚠️  Warning: Running SSE server without TLS (Not Recommended)")
	return httpServer.ListenAndServe()
}

func createMCPServer() *server.MCPServer {
	s := server.NewMCPServer("Maknoon PQC Server", "1.3.2", server.WithLogging())
	engine := GlobalContext.Engine

	// Helper to extract arguments from mcp-go v0.48.0 request
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
			if err != nil {
				return formatMCPError(err, "vault_get")
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
				return formatMCPError(err, "vault_set")
			}
			return mcp.NewToolResultText(`{"status":"success"}`), nil
		})

	// 2. Crypto Tools
	s.AddTool(mcp.NewTool("encrypt_file", mcp.WithDescription("Encrypt a file")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			opts := crypto.Options{ProfileID: 1}

			passRaw := viper.GetString("passphrase")
			if passRaw != "" {
				opts.Passphrase = []byte(passRaw)
			}

			if pk := getString(args, "public_key", ""); pk != "" {
				m := crypto.NewIdentityManager()
				if res := m.ResolveKeyPath(pk, ""); res != "" {
					data, err := os.ReadFile(res)
					if err == nil {
						opts.Recipients = append(opts.Recipients, data)
					}
				}
			}

			input := getString(args, "input", "")
			output := getString(args, "output", "")

			in, err := os.Open(input)
			if err != nil {
				return formatMCPError(err, "encrypt_file")
			}
			defer in.Close()

			out, err := os.Create(output)
			if err != nil {
				return formatMCPError(err, "encrypt_file")
			}
			defer out.Close()

			_, err = engine.Protect(nil, "", in, out, opts)
			if err != nil {
				return formatMCPError(err, "encrypt_file")
			}
			return mcp.NewToolResultText(`{"status":"success"}`), nil
		})

	s.AddTool(mcp.NewTool("inspect_file", mcp.WithDescription("Analyze header metadata")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			in, _ := os.Open(getString(args, "path", ""))
			info, err := engine.Inspect(nil, in)
			if err != nil {
				return formatMCPError(err, "inspect_file")
			}
			res, _ := json.Marshal(info)
			return mcp.NewToolResultText(string(res)), nil
		})

	// 3. P2P & Network Tools
	s.AddTool(mcp.NewTool("tunnel_start", mcp.WithDescription("Provision a Post-Quantum L4 tunnel and SOCKS5 gateway")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			remote := getString(args, "remote", "")
			port, _ := args["port"].(float64)
			if port == 0 {
				port = 1080 // Default SOCKS5 port
			}

			opts := tunnel.TunnelOptions{
				RemoteEndpoint: remote,
				LocalProxyPort: int(port),
			}

			status, err := engine.TunnelStart(nil, opts)
			if err != nil {
				return formatMCPError(err, "tunnel_start")
			}
			res, _ := json.Marshal(status)
			return mcp.NewToolResultText(string(res)), nil
		})

	s.AddTool(mcp.NewTool("tunnel_stop", mcp.WithDescription("Terminate the active PQC tunnel")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			err := engine.TunnelStop(nil)
			if err != nil {
				return formatMCPError(err, "tunnel_stop")
			}
			return mcp.NewToolResultText(`{"status":"stopped"}`), nil
		})

	s.AddTool(mcp.NewTool("tunnel_status", mcp.WithDescription("Retrieve status of the active tunnel")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			status, err := engine.TunnelStatus(nil)
			if err != nil {
				return formatMCPError(err, "tunnel_status")
			}
			res, _ := json.Marshal(status)
			return mcp.NewToolResultText(string(res)), nil
		})

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
				Stealth:    getBool(args, "stealth", false),
			}
			code, _, err := engine.P2PSend(nil, name, r, opts)
			if err != nil {
				return formatMCPError(err, "p2p_send")
			}
			return mcp.NewToolResultText(fmt.Sprintf(`{"code":"%s","status":"established"}`, code)), nil
		})

	s.AddTool(mcp.NewTool("start_chat", mcp.WithDescription("Initiate a Ghost Chat session")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			session := crypto.NewChatSession("maknoon-mcp")
			code, err := session.StartHost(ctx)
			if err != nil {
				return formatMCPError(err, "start_chat")
			}
			session.Close()
			return mcp.NewToolResultText(fmt.Sprintf(`{"status":"established","code":"%s"}`, code)), nil
		})

	// 4. Utility Tools
	s.AddTool(mcp.NewTool("gen_passphrase", mcp.WithDescription("Generate a secure mnemonic")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			words, _ := args["words"].(float64)
			pass, err := engine.GeneratePassphrase(nil, int(words), "-")
			if err != nil {
				return formatMCPError(err, "gen_passphrase")
			}
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
