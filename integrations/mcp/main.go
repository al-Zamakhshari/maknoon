package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func initEngine() (crypto.MaknoonEngine, error) {
	os.Setenv("MAKNOON_AGENT_MODE", "1")
	policy := &crypto.AgentPolicy{}
	core, err := crypto.NewEngine(policy)
	if err != nil { return nil, err }
	return &crypto.AuditEngine{
		Engine: core,
		Logger: slog.Default(),
		Audit:  &crypto.NoopLogger{},
	}, nil
}

func createServer(engine crypto.MaknoonEngine) *server.MCPServer {
	s := server.NewMCPServer("Maknoon PQC Agent", "1.3.2")

	getArgs := func(request mcp.CallToolRequest) map[string]interface{} {
		args, _ := request.Params.Arguments.(map[string]interface{})
		return args
	}

	getString := func(args map[string]any, key string, def string) string {
		if val, ok := args[key].(string); ok { return val }
		return def
	}

	// 1. Tool: identity_active
	s.AddTool(mcp.NewTool("identity_active", mcp.WithDescription("List currently active post-quantum identities")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ectx := crypto.NewEngineContext(ctx, nil, nil)
			identities, err := engine.IdentityActive(ectx)
			if err != nil { return formatError(err, "identity_active") }
			res, _ := json.Marshal(map[string]any{"status": "success", "identities": identities})
			return mcp.NewToolResultText(string(res)), nil
		})

	// 2. Tool: vault_list
	s.AddTool(mcp.NewTool("vault_list", mcp.WithDescription("List all services stored in a PQC vault")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			vaultPath := getString(args, "vault", "default")
			ectx := crypto.NewEngineContext(ctx, nil, nil)
			services, err := engine.VaultList(ectx, vaultPath)
			if err != nil { return formatError(err, "vault_list") }
			res, _ := json.Marshal(map[string]any{"status": "success", "services": services})
			return mcp.NewToolResultText(string(res)), nil
		})

	// 3. Tool: vault_get
	s.AddTool(mcp.NewTool("vault_get", mcp.WithDescription("Retrieve a credential from the PQC vault")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			service := getString(args, "service", "")
			pass := getString(args, "passphrase", "")
			pin := getString(args, "pin", "")
			vault := getString(args, "vault", "default")
			ectx := crypto.NewEngineContext(ctx, nil, nil)
			entry, err := engine.VaultGet(ectx, vault, service, []byte(pass), pin)
			if err != nil { return formatError(err, "vault_get") }
			res, _ := json.Marshal(entry)
			return mcp.NewToolResultText(string(res)), nil
		})

	// 4. Tool: vault_set
	s.AddTool(mcp.NewTool("vault_set", mcp.WithDescription("Store a credential in the PQC vault")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			service := getString(args, "service", "")
			username := getString(args, "username", "")
			password := getString(args, "password", "")
			pass := getString(args, "passphrase", "")
			pin := getString(args, "pin", "")
			vault := getString(args, "vault", "default")
			ectx := crypto.NewEngineContext(ctx, nil, nil)
			err := engine.VaultSet(ectx, vault, &crypto.VaultEntry{Service: service, Username: username, Password: []byte(password)}, []byte(pass), pin)
			if err != nil { return formatError(err, "vault_set") }
			return mcp.NewToolResultText(`{"status":"success"}`), nil
		})

	// 5. Tool: encrypt_file
	s.AddTool(mcp.NewTool("encrypt_file", mcp.WithDescription("Protect a file using Post-Quantum encryption")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			input := getString(args, "input", "")
			output := getString(args, "output", "")
			pass := getString(args, "passphrase", "")
			
			f, err := os.Open(input)
			if err != nil { return formatError(err, "encrypt_file") }
			defer f.Close()
			out, err := os.Create(output)
			if err != nil { return formatError(err, "encrypt_file") }
			defer out.Close()

			ectx := crypto.NewEngineContext(ctx, nil, nil)
			_, err = engine.Protect(ectx, input, f, out, crypto.Options{Passphrase: []byte(pass)})
			if err != nil { return formatError(err, "encrypt_file") }
			return mcp.NewToolResultText(`{"status":"success"}`), nil
		})

	// 6. Tool: decrypt_file
	s.AddTool(mcp.NewTool("decrypt_file", mcp.WithDescription("Unprotect a file using Post-Quantum decryption")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			input := getString(args, "input", "")
			output := getString(args, "output", "")
			pass := getString(args, "passphrase", "")

			f, err := os.Open(input)
			if err != nil { return formatError(err, "decrypt_file") }
			defer f.Close()
			out, err := os.Create(output)
			if err != nil { return formatError(err, "decrypt_file") }
			defer out.Close()

			ectx := crypto.NewEngineContext(ctx, nil, nil)
			_, err = engine.Unprotect(ectx, f, out, output, crypto.Options{Passphrase: []byte(pass)})
			if err != nil { return formatError(err, "decrypt_file") }
			return mcp.NewToolResultText(`{"status":"success"}`), nil
		})

	// 7. Tool: inspect_file
	s.AddTool(mcp.NewTool("inspect_file", mcp.WithDescription("Reveal metadata about a Maknoon protected file")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			input := getString(args, "input", "")
			f, err := os.Open(input)
			if err != nil { return formatError(err, "inspect_file") }
			defer f.Close()
			ectx := crypto.NewEngineContext(ctx, nil, nil)
			info, err := engine.Inspect(ectx, f)
			if err != nil { return formatError(err, "inspect_file") }
			res, _ := json.Marshal(info)
			return mcp.NewToolResultText(string(res)), nil
		})

	// 8. Tool: gen_password
	s.AddTool(mcp.NewTool("gen_password", mcp.WithDescription("Generate a cryptographically secure random password")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			length, _ := args["length"].(float64)
			if length == 0 { length = 32 }
			noSymbols, _ := args["noSymbols"].(bool)
			ectx := crypto.NewEngineContext(ctx, nil, nil)
			pass, err := engine.GeneratePassword(ectx, int(length), noSymbols)
			if err != nil { return formatError(err, "gen_password") }
			res, _ := json.Marshal(map[string]any{"status": "success", "password": pass})
			return mcp.NewToolResultText(string(res)), nil
		})

	// 9. Tool: gen_passphrase
	s.AddTool(mcp.NewTool("gen_passphrase", mcp.WithDescription("Generate a high-entropy mnemonic passphrase")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			words, _ := args["words"].(float64)
			if words == 0 { words = 12 }
			sep := getString(args, "separator", "-")
			ectx := crypto.NewEngineContext(ctx, nil, nil)
			pass, err := engine.GeneratePassphrase(ectx, int(words), sep)
			if err != nil { return formatError(err, "gen_passphrase") }
			res, _ := json.Marshal(map[string]any{"status": "success", "passphrase": pass})
			return mcp.NewToolResultText(string(res)), nil
		})

	// 10. Tool: tunnel_listen
	s.AddTool(mcp.NewTool("tunnel_listen", mcp.WithDescription("Start a PQC Tunnel listener")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			addr := getString(args, "address", ":4433")
			w, _ := args["wormhole"].(bool)
			ectx := crypto.NewEngineContext(ctx, nil, nil)
			code, _, err := engine.TunnelListen(ectx, addr, w)
			if err != nil { return formatError(err, "tunnel_listen") }
			res, _ := json.Marshal(map[string]any{"status": "listening", "code": code, "addr": addr})
			return mcp.NewToolResultText(string(res)), nil
		})

	// 11. Tool: tunnel_start
	s.AddTool(mcp.NewTool("tunnel_start", mcp.WithDescription("Start a PQC Tunnel client")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			remote := getString(args, "remote", "")
			code := getString(args, "code", "")
			port, _ := args["port"].(float64)
			if port == 0 { port = 1080 }

			ectx := crypto.NewEngineContext(ctx, nil, nil)
			status, err := engine.TunnelStart(ectx, tunnel.TunnelOptions{
				RemoteEndpoint: remote, WormholeCode: code, LocalProxyPort: int(port),
			})
			if err != nil { return formatError(err, "tunnel_start") }
			res, _ := json.Marshal(status)
			return mcp.NewToolResultText(string(res)), nil
		})

	return s
}

func formatError(err error, toolName string) (*mcp.CallToolResult, error) {
	resp := map[string]interface{}{ "status": "error", "tool": toolName, "error": err.Error() }
	res, _ := json.Marshal(resp)
	return mcp.NewToolResultText(string(res)), nil
}

func main() {
	engine, err := initEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize engine: %v\n", err)
		os.Exit(1)
	}

	s := createServer(engine)
	
	transport := "stdio"
	if len(os.Args) > 1 && strings.Contains(os.Args[1], "sse") { transport = "sse" }

	if transport == "sse" {
		addr := ":8080"
		sse := server.NewSSEServer(s, server.WithBaseURL("http://localhost"+addr))
		fmt.Printf("🚀 Starting PQC MCP SSE Server on %s\n", addr)
		if err := http.ListenAndServe(addr, sse); err != nil {
			fmt.Fprintf(os.Stderr, "SSE server error: %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := server.ServeStdio(s); err != nil {
			fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
			os.Exit(1)
		}
	}
}
