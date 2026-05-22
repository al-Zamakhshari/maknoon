package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// ServeIdentityCmd returns the WKD identity HTTP server command.
func ServeIdentityCmd() *cobra.Command {
	var addr string
	var keysDir string

	cmd := &cobra.Command{
		Use:   "serve-identity",
		Short: "Serve identity records via WKD (Web Key Directory) over HTTP",
		Long: `Starts an HTTP server that serves your Maknoon identity records at:

  GET /.well-known/maknoon/<localpart>.json

This lets others resolve your public keys without needing a full web server.
Point a reverse proxy (nginx, caddy) at this server for TLS termination.

The server discovers identities from the keys directory and signs each
response with the corresponding signing key on the fly.

Example:
  maknoon serve-identity --address :8080
  # Then configure nginx to proxy /.well-known/maknoon/ to :8080`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if keysDir == "" {
				conf := GlobalContext.Engine.GetConfig()
				keysDir = conf.Paths.KeysDir
			}
			return runServeIdentity(addr, keysDir)
		},
	}

	cmd.Flags().StringVar(&addr, "address", ":8080", "Listen address")
	cmd.Flags().StringVar(&keysDir, "keys-dir", "", "Keys directory (default: configured KeysDir)")
	return cmd
}

func runServeIdentity(addr, keysDir string) error {
	mux := http.NewServeMux()

	// WKD endpoint: GET /.well-known/maknoon/<localpart>.json
	mux.Handle("/.well-known/maknoon/", rateLimitMiddleware(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			// Extract localpart from path: /.well-known/maknoon/<localpart>.json
			path := strings.TrimPrefix(r.URL.Path, "/.well-known/maknoon/")
			localpart := strings.TrimSuffix(path, ".json")
			if localpart == "" || strings.ContainsAny(localpart, "/\\..") {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			localpart = strings.ToLower(localpart)

			record, err := buildIdentityRecord(keysDir, localpart)
			if err != nil {
				http.Error(w, "identity not found", http.StatusNotFound)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=300")
			_ = json.NewEncoder(w).Encode(record)
		})))

	// Health probe
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	fmt.Fprintf(os.Stderr, "%s Serving WKD identity records on %s\n",
		icon("🌐", ">>"), addr)
	fmt.Fprintf(os.Stderr, "  Keys directory: %s\n", keysDir)
	fmt.Fprintf(os.Stderr, "  Endpoint: http://<host>%s/.well-known/maknoon/<localpart>.json\n\n", addr)

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "serve-identity: %v\n", err)
		}
	}()

	<-stop
	fmt.Fprintln(os.Stderr, "\nShutting down serve-identity...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

// buildIdentityRecord reads key files for the given localpart and returns a signed
// IdentityRecord. The localpart must match a key file base name in keysDir.
func buildIdentityRecord(keysDir, localpart string) (*crypto.IdentityRecord, error) {
	kemPubPath := filepath.Join(keysDir, localpart+".kem.pub")
	sigPubPath := filepath.Join(keysDir, localpart+".sig.pub")
	sigPrivPath := filepath.Join(keysDir, localpart+".sig.key")

	kemPub, err := os.ReadFile(kemPubPath)
	if err != nil {
		return nil, fmt.Errorf("KEM public key not found for %q", localpart)
	}
	sigPub, err := os.ReadFile(sigPubPath)
	if err != nil {
		return nil, fmt.Errorf("SIG public key not found for %q", localpart)
	}

	record := &crypto.IdentityRecord{
		Handle:    "@" + localpart,
		KEMPubKey: kemPub,
		SIGPubKey: sigPub,
		Timestamp: time.Now(),
		ExpiresAt: time.Now().Add(48 * time.Hour),
	}

	// Sign the record if the private signing key is accessible (no passphrase).
	if sigPriv, err := os.ReadFile(sigPrivPath); err == nil {
		_ = record.Sign(sigPriv)
		crypto.SafeClear(sigPriv)
	}

	return record, nil
}
