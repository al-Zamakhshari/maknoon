package commands

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/time/rate"
)

// Rate limiting settings (5 requests/sec with burst of 10)
var globalLimiter = rate.NewLimiter(rate.Every(200*time.Millisecond), 10)

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !globalLimiter.Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error":  "too many requests",
				"status": "fail",
				"retry":  "please slow down, PQC operations are compute-intensive",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ServeCmd returns the cobra command for launching the Maknoon API server.
func ServeCmd() *cobra.Command {
	var addr string
	var certFile, keyFile string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Maknoon PQC API Server (MCP/SSE)",
		Long: `Launches the Maknoon API server. All cryptographic and vault operations
are exposed via the MCP SSE transport. Kubernetes liveness and readiness probes
are available at /v1/live and /v1/ready respectively.

The server mandates Post-Quantum TLS 1.3 (ML-KEM hybrid) for all connections,
ensuring a zero-trust, quantum-resistant infrastructure.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = viper.BindPFlag("server.address", cmd.Flags().Lookup("address"))
			_ = viper.BindPFlag("server.tls_cert", cmd.Flags().Lookup("tls-cert"))
			_ = viper.BindPFlag("server.tls_key", cmd.Flags().Lookup("tls-key"))

			// Initialize engine in agent mode for API safety (non-interactive)
			viper.Set("agent_mode", "1")
			if err := InitEngine(); err != nil {
				return fmt.Errorf("failed to initialize engine: %w", err)
			}

			return runAPIServer()
		},
	}

	cmd.Flags().StringVar(&addr, "address", ":8081", "Address to listen on")
	cmd.Flags().StringVar(&certFile, "tls-cert", "", "Path to TLS certificate (REQUIRED)")
	cmd.Flags().StringVar(&keyFile, "tls-key", "", "Path to TLS private key (REQUIRED)")

	return cmd
}

func runAPIServer() error {
	addr := viper.GetString("server.address")
	certFile := viper.GetString("server.tls_cert")
	keyFile := viper.GetString("server.tls_key")

	if certFile == "" || keyFile == "" {
		return fmt.Errorf("TLS is REQUIRED for API Server mode. Maknoon mandates Post-Quantum Secure transport for all cryptographic services")
	}

	// Initial certificate load
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificates: %w", err)
	}
	SetActiveCertificate(cert)

	// Background hot-reload handler (SIGHUP)
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGHUP)
		for range sigChan {
			newCert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				fmt.Printf("Failed to reload certificates: %v\n", err)
				continue
			}
			SetActiveCertificate(newCert)
			fmt.Println("TLS certificates reloaded successfully")
		}
	}()

	// Build the MCP server and attach its SSE transport.
	mcpServer := createMCPServer()

	mux := http.NewServeMux()

	// Kubernetes probe endpoints (no MCP equivalent for these).
	mux.HandleFunc("/v1/health", handleHealth)
	mux.HandleFunc("/v1/live", handleLive)
	mux.HandleFunc("/v1/ready", handleReady)

	// Route all other requests to the MCP SSE transport.
	sseServer := server.NewSSEServer(mcpServer, server.WithBaseURL("https://"+addr))
	mux.Handle("/", sseServer)

	// Define the HTTP server with Post-Quantum TLS 1.3 configuration
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           rateLimitMiddleware(mux),
		TLSConfig:         GetTLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB header limit
	}

	// Graceful shutdown on SIGTERM / SIGINT
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if GlobalContext.Engine != nil {
			type shutdowner interface {
				Shutdown(ctx context.Context) error
			}
			if s, ok := GlobalContext.Engine.(shutdowner); ok {
				_ = s.Shutdown(shutCtx)
			} else {
				_ = GlobalContext.Engine.Close()
			}
		}
		_ = httpServer.Shutdown(shutCtx)
	}()

	fmt.Printf("Starting Maknoon PQC API Server on %s\n", addr)
	fmt.Println("Transport encryption active (PQ-TLS 1.3)")
	return httpServer.ListenAndServeTLS(certFile, keyFile)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "pass", "version": "4.1.0"})
}

// handleLive is a Kubernetes liveness probe — always returns 200 as long as the process is running.
func handleLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "alive"})
}

// handleReady is a Kubernetes readiness probe — returns 200 only when the engine is fully
// initialized and the vault directory is accessible.
func handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if GlobalContext.Engine == nil {
		http.Error(w, `{"status":"not ready","reason":"engine not initialized"}`, http.StatusServiceUnavailable)
		return
	}
	conf := GlobalContext.Engine.GetConfig()
	vaultsDir := conf.Paths.VaultsDir
	if vaultsDir == "" {
		vaultsDir = crypto.GetUserHomeDir() + "/.maknoon/vaults"
	}
	if _, err := os.Stat(vaultsDir); err != nil {
		http.Error(w, `{"status":"not ready","reason":"vault directory not accessible"}`, http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}
