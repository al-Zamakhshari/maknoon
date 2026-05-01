package commands

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

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

	sseServer := server.NewSSEServer(s, server.WithBaseURL("http://"+addr))

	// Define the HTTP server with Post-Quantum TLS 1.3 configuration
	httpServer := &http.Server{
		Addr: addr,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{
				tls.X25519MLKEM768,
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
	s := server.NewMCPServer("Maknoon PQC Server", "4.0.0", server.WithLogging())
	engine := GlobalContext.Engine

	// Register Categorized Tools
	registerVaultTools(s, engine)
	registerCryptoTools(s, engine)
	registerNetworkTools(s, engine)
	registerConfigTools(s, engine)
	registerIdentityTools(s, engine)
	registerProfilesTools(s, engine)

	return s
}
