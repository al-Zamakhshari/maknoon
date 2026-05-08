package commands

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
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
	var backend string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Maknoon PQC API Server",
		Long: `Launches the Maknoon API server. This provides a secure RESTful interface 
for cryptographic operations, vault management, and identity signing.

The server mandates Post-Quantum TLS 1.3 (ML-KEM hybrid) for all connections, 
ensuring a zero-trust, quantum-resistant infrastructure.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = viper.BindPFlag("server.address", cmd.Flags().Lookup("address"))
			_ = viper.BindPFlag("server.tls_cert", cmd.Flags().Lookup("tls-cert"))
			_ = viper.BindPFlag("server.tls_key", cmd.Flags().Lookup("tls-key"))
			_ = viper.BindPFlag("vault_backend", cmd.Flags().Lookup("backend"))

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
	cmd.Flags().StringVar(&backend, "backend", "bbolt", "Vault storage backend (bbolt or badger)")

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
				fmt.Printf("⚠️  Failed to reload certificates: %v\n", err)
				continue
			}
			SetActiveCertificate(newCert)
			fmt.Println("🔄 TLS certificates reloaded successfully")
		}
	}()

	mux := http.NewServeMux()

	// Register REST API routes
	mux.HandleFunc("/v1/health", handleHealth)
	mux.HandleFunc("/v1/vault/get", handleVaultGet)
	mux.HandleFunc("/v1/vault/set", handleVaultSet)
	mux.HandleFunc("/v1/vault/rotate", handleVaultRotate)
	mux.HandleFunc("/v1/vault/check-shards", handleVaultCheckShards)
	mux.HandleFunc("/v1/identity/sign", handleSign)
	mux.HandleFunc("/v1/identity/sign/aggregate", handleAggregateSignatures)
	mux.HandleFunc("/v1/identity/verify", handleVerify)
	mux.HandleFunc("/v1/identity/resolve", handleResolve)
	mux.HandleFunc("/v1/audit/export", handleAuditExport)

	// Crypto & Dispersal
	mux.HandleFunc("/v1/crypto/fragment", handleFragment)
	mux.HandleFunc("/v1/crypto/reassemble", handleReassemble)
	mux.HandleFunc("/v1/crypto/wrap", handleWrap)
	mux.HandleFunc("/v1/crypto/unwrap", handleUnwrap)

	// KMS & Network Orchestration
	mux.HandleFunc("/v1/network/tunnel/start", handleTunnelStart)
	mux.HandleFunc("/v1/network/tunnel/stop", handleTunnelStop)

	// Define the HTTP server with Post-Quantum TLS 1.3 configuration
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           rateLimitMiddleware(mux),
		TLSConfig:         GetTLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("🚀 Starting Maknoon PQC API Server on %s\n", addr)
	fmt.Println("🔒 Transport encryption active (PQ-TLS 1.3)")
	return httpServer.ListenAndServeTLS(certFile, keyFile)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "pass", "version": "4.1.0"})
}

// REST Handlers (Implementation of engine primitives)

func handleVaultGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Vault      string `json:"vault"`
		Service    string `json:"service"`
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	entry, err := GlobalContext.Engine.VaultGet(nil, req.Vault, req.Service, []byte(req.Passphrase), "")
	if err != nil {
		renderAPIError(w, err)
		return
	}

	renderAPISuccess(w, entry)
}

func handleVaultSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Vault      string `json:"vault"`
		Service    string `json:"service"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		Passphrase string `json:"passphrase"`
		Overwrite  bool   `json:"overwrite"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	entry := &crypto.VaultEntry{
		Service:  req.Service,
		Username: req.Username,
		Password: crypto.SecretBytes(req.Password),
	}

	err := GlobalContext.Engine.VaultSet(nil, req.Vault, entry, []byte(req.Passphrase), "", req.Overwrite)
	if err != nil {
		renderAPIError(w, err)
		return
	}

	renderAPISuccess(w, map[string]string{"status": "success"})
}

func handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		DataB64    string `json:"data"`
		KeyPath    string `json:"key_path"`
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.DataB64)
	if err != nil {
		http.Error(w, "invalid base64 data: "+err.Error(), http.StatusBadRequest)
		return
	}

	privKey, err := GlobalContext.Engine.LoadPrivateKey(nil, req.KeyPath, []byte(req.Passphrase), "", true)
	if err != nil {
		renderAPIError(w, fmt.Errorf("failed to load private key: %w", err))
		return
	}

	sig, err := GlobalContext.Engine.Sign(nil, data, privKey)
	if err != nil {
		renderAPIError(w, fmt.Errorf("signing failed: %w", err))
		return
	}

	renderAPISuccess(w, map[string]any{"signature": base64.StdEncoding.EncodeToString(sig)})
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		DataB64      string   `json:"data"`
		SignatureB64 string   `json:"signature"`
		PublicKeyB64 string   `json:"public_key"`
		PublicKeys   []string `json:"public_keys"`
		Threshold    int      `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.DataB64)
	if err != nil {
		http.Error(w, "invalid base64 data", http.StatusBadRequest)
		return
	}

	sig, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil {
		http.Error(w, "invalid base64 signature", http.StatusBadRequest)
		return
	}

	var pubKeys [][]byte
	for i, pkB64 := range req.PublicKeys {
		pk, err := base64.StdEncoding.DecodeString(pkB64)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid base64 public key at index %d", i), http.StatusBadRequest)
			return
		}
		pubKeys = append(pubKeys, pk)
	}
	if req.PublicKeyB64 != "" {
		pk, err := base64.StdEncoding.DecodeString(req.PublicKeyB64)
		if err != nil {
			http.Error(w, "invalid base64 public key", http.StatusBadRequest)
			return
		}
		pubKeys = append(pubKeys, pk)
	}

	var valid bool
	if req.Threshold > 1 || len(pubKeys) > 1 {
		valid, err = GlobalContext.Engine.VerifyThreshold(nil, data, sig, pubKeys, req.Threshold)
	} else {
		if len(pubKeys) == 0 {
			http.Error(w, "public key required", http.StatusBadRequest)
			return
		}
		valid, err = GlobalContext.Engine.Verify(nil, data, sig, pubKeys[0])
	}

	if err != nil {
		renderAPIError(w, fmt.Errorf("verification failed: %w", err))
		return
	}

	renderAPISuccess(w, map[string]bool{"valid": valid})
}

func handleAggregateSignatures(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Signatures []string `json:"signatures"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var sigs [][]byte
	for i, sB64 := range req.Signatures {
		s, err := base64.StdEncoding.DecodeString(sB64)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid base64 signature at index %d", i), http.StatusBadRequest)
			return
		}
		sigs = append(sigs, s)
	}

	agg, err := GlobalContext.Engine.Aggregate(nil, sigs)
	if err != nil {
		renderAPIError(w, fmt.Errorf("aggregation failed: %w", err))
		return
	}

	renderAPISuccess(w, map[string]any{"signature": base64.StdEncoding.EncodeToString(agg)})
}

func handleFragment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Input        string `json:"input"`
		Output       string `json:"output"`
		DataShards   int    `json:"data_shards"`
		ParityShards int    `json:"parity_shards"`
		SignWith     string `json:"sign_with"`
		Passphrase   string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.DataShards == 0 {
		req.DataShards = 5
	}
	if req.ParityShards == 0 {
		req.ParityShards = 3
	}
	if req.Output == "" {
		req.Output = req.Input + "_fragments"
	}

	fi, err := os.Stat(req.Input)
	if err != nil {
		renderAPIError(w, err)
		return
	}

	in, err := os.Open(req.Input)
	if err != nil {
		renderAPIError(w, err)
		return
	}
	defer in.Close()

	var sigKey []byte
	if req.SignWith != "" {
		sigKey, err = GlobalContext.Engine.LoadPrivateKey(nil, req.SignWith, []byte(req.Passphrase), "", true)
		if err != nil {
			renderAPIError(w, err)
			return
		}
		defer crypto.SafeClear(sigKey)
	}

	opts := crypto.FragmentOptions{
		DataShards:   req.DataShards,
		ParityShards: req.ParityShards,
		TargetDir:    req.Output,
		OriginalSize: fi.Size(),
		SigningKey:   sigKey,
	}

	fw, err := crypto.NewFragmentWriter(opts)
	if err != nil {
		renderAPIError(w, err)
		return
	}
	defer fw.Close()

	if _, err := io.Copy(fw, in); err != nil {
		renderAPIError(w, err)
		return
	}

	renderAPISuccess(w, map[string]any{
		"status":    "success",
		"shards":    req.DataShards + req.ParityShards,
		"directory": req.Output,
	})
}

func handleReassemble(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		InputDir      string `json:"input_dir"`
		Output        string `json:"output"`
		AuthorizedKey []byte `json:"authorized_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Output == "" {
		req.Output = "restored.data"
	}

	f, err := os.Create(req.Output)
	if err != nil {
		renderAPIError(w, err)
		return
	}
	defer f.Close()

	if err := GlobalContext.Engine.ReassembleFragments(req.InputDir, f, req.AuthorizedKey); err != nil {
		renderAPIError(w, err)
		return
	}

	renderAPISuccess(w, map[string]any{
		"status": "success",
		"file":   req.Output,
	})
}

func handleResolve(w http.ResponseWriter, r *http.Request) {
	handle := r.URL.Query().Get("handle")
	if handle == "" {
		http.Error(w, "handle parameter is required", http.StatusBadRequest)
		return
	}

	pubKey, err := GlobalContext.Engine.ResolvePublicKey(nil, handle, true)
	if err != nil {
		renderAPIError(w, err)
		return
	}

	renderAPISuccess(w, map[string]any{
		"handle":     handle,
		"public_key": pubKey,
	})
}

func handleAuditExport(w http.ResponseWriter, r *http.Request) {
	entries, err := GlobalContext.Engine.AuditExport(nil)
	if err != nil {
		renderAPIError(w, err)
		return
	}

	renderAPISuccess(w, entries)
}

func handleWrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	pubKey, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		http.Error(w, "invalid hex public key: "+err.Error(), http.StatusBadRequest)
		return
	}

	res, err := GlobalContext.Engine.Wrap(nil, pubKey)
	if err != nil {
		renderAPIError(w, err)
		return
	}

	renderAPISuccess(w, map[string]any{
		"plaintext": hex.EncodeToString(res.Plaintext),
		"wrapped":   hex.EncodeToString(res.Wrapped),
	})
}

func handleUnwrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		WrappedKey string `json:"wrapped_key"`
		KeyPath    string `json:"key_path"`
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	wrappedKey, err := hex.DecodeString(req.WrappedKey)
	if err != nil {
		http.Error(w, "invalid hex wrapped key: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Resolve the key path (handle base names and full paths)
	resolvedPath := GlobalContext.Engine.ResolveKeyPath(nil, req.KeyPath, "")
	if resolvedPath == "" {
		// Try resolving as a base name with .kem.key suffix
		resolvedPath = GlobalContext.Engine.ResolveKeyPath(nil, req.KeyPath+".kem.key", "")
	}
	if resolvedPath == "" {
		resolvedPath = req.KeyPath // Fallback to raw path
	}

	privKey, err := GlobalContext.Engine.LoadPrivateKey(nil, resolvedPath, []byte(req.Passphrase), "", true)
	if err != nil {
		renderAPIError(w, err)
		return
	}

	res, err := GlobalContext.Engine.Unwrap(nil, wrappedKey, privKey)
	if err != nil {
		renderAPIError(w, err)
		return
	}

	renderAPISuccess(w, map[string]any{
		"plaintext": hex.EncodeToString(res),
	})
}

func handleVaultRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Vault         string `json:"vault"`
		OldPassphrase string `json:"old_passphrase"`
		NewPassphrase string `json:"new_passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := GlobalContext.Engine.VaultRotate(nil, req.Vault, []byte(req.OldPassphrase), []byte(req.NewPassphrase))
	if err != nil {
		renderAPIError(w, err)
		return
	}

	renderAPISuccess(w, map[string]string{
		"status":  "success",
		"message": "Vault passphrase rotated successfully",
	})
}

func handleVaultCheckShards(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Shards []string `json:"shards"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res, err := GlobalContext.Engine.VaultCheckShards(nil, req.Shards)
	if err != nil {
		renderAPIError(w, err)
		return
	}

	renderAPISuccess(w, res)
}

func handleTunnelStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var opts tunnel.TunnelOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	status, err := GlobalContext.Engine.TunnelStart(nil, opts)
	if err != nil {
		renderAPIError(w, err)
		return
	}

	renderAPISuccess(w, status)
}

func handleTunnelStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	err := GlobalContext.Engine.TunnelStop(nil)
	if err != nil {
		renderAPIError(w, err)
		return
	}

	renderAPISuccess(w, map[string]string{"status": "stopped"})
}

// API Rendering Helpers

func renderAPISuccess(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func renderAPIError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
