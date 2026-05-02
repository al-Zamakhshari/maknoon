package commands

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func CallCmd() *cobra.Command {
	var addr string
	var argsStr string
	var insecure bool

	cmd := &cobra.Command{
		Use:   "call [tool_name]",
		Short: "Invoke an MCP tool on a running Maknoon agent via a standard SSE client",
		Long: `Invokes an MCP tool using a standard SSE client. 
By default, this command uses HTTPS with Post-Quantum TLS 1.3 (ML-KEM) 
to ensure a quantum-resistant orchestration handshake.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			toolName := args[0]
			ctx := context.Background()

			var arguments map[string]any
			if argsStr != "" {
				if err := json.Unmarshal([]byte(argsStr), &arguments); err != nil {
					return fmt.Errorf("invalid JSON arguments: %v", err)
				}
			}

			// Ensure address has protocol and standard SSE path
			baseURL := addr
			if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
				baseURL = "https://" + baseURL
			}
			if !strings.HasSuffix(baseURL, "/sse") {
				baseURL = strings.TrimSuffix(baseURL, "/") + "/sse"
			}

			// Configure HTTP Client with PQC-preferring TLS
			tlsConfig := &tls.Config{
				InsecureSkipVerify: insecure,
				MinVersion:         tls.VersionTLS13,
				CurvePreferences: []tls.CurveID{
					tls.X25519MLKEM768,
					tls.X25519,
				},
			}
			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
			}

			// STANDARD PATH: Formal MCP Client Lifecycle
			if viper.GetBool("trace") {
				fmt.Fprintf(os.Stderr, "TRACE: Initializing standard MCP SSE client for %s\n", baseURL)
			}
			mcpClient, err := client.NewSSEMCPClient(baseURL, transport.WithHTTPClient(httpClient))
			if err != nil {
				return fmt.Errorf("failed to create MCP client: %v", err)
			}
			defer mcpClient.Close()

			// 1. Start (begins SSE event loop and connects)
			if viper.GetBool("trace") {
				fmt.Fprintf(os.Stderr, "TRACE: Starting SSE event loop...\n")
			}
			if err := mcpClient.Start(ctx); err != nil {
				return fmt.Errorf("failed to start client: %v", err)
			}

			// 2. Initialize (Handshake)
			initReq := mcp.InitializeRequest{
				Params: mcp.InitializeParams{
					ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
					ClientInfo: mcp.Implementation{
						Name:    "maknoon-orchestrator",
						Version: "v1.0",
					},
				},
			}
			if viper.GetBool("trace") {
				fmt.Fprintf(os.Stderr, "TRACE: Sending Initialize request...\n")
			}
			if _, err := mcpClient.Initialize(ctx, initReq); err != nil {
				return fmt.Errorf("initialization failed: %v", err)
			}

			// 3. Call Tool
			callReq := mcp.CallToolRequest{
				Params: mcp.CallToolParams{
					Name:      toolName,
					Arguments: arguments,
				},
			}
			if viper.GetBool("trace") {
				fmt.Fprintf(os.Stderr, "TRACE: Calling tool '%s'...\n", toolName)
			}

			result, err := mcpClient.CallTool(ctx, callReq)
			if err != nil {
				return fmt.Errorf("tool execution failed: %v", err)
			}

			// Render result as JSON
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(result)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "localhost:8080", "Address of the running Maknoon agent")
	cmd.Flags().StringVar(&argsStr, "args", "", "JSON string of tool arguments")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "Skip TLS certificate verification (ONLY FOR TESTING)")
	return cmd
}
