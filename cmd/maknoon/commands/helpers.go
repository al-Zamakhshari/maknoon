package commands

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

// GlobalContext stores shared state for CLI commands.
var GlobalContext struct {
	Engine     crypto.MaknoonEngine
	JSONOutput bool
	JSONWriter io.Writer
	UI         *UIHandler
}

// UIHandler manages user-facing output with awareness of interactivity and formatting.
type UIHandler struct {
	Stdout      io.Writer
	Stderr      io.Writer
	Interactive bool
	JSON        bool
}

// Presenter defines the interface for rendering engine results.
type Presenter interface {
	RenderSuccess(result any)
	RenderError(err error)
	RenderMessage(msg string)
}

// JSONPresenter renders results as pretty-printed JSON.
type JSONPresenter struct {
	Writer io.Writer
}

func (p *JSONPresenter) RenderSuccess(result any) {
	if p.Writer == nil {
		return
	}
	enc := json.NewEncoder(p.Writer)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
}

func (p *JSONPresenter) RenderError(err error) {
	resp := map[string]any{"status": "error", "error": err.Error()}
	var policyErr *crypto.ErrPolicyViolation
	if crypto.As(err, &policyErr) {
		resp["type"] = "security_policy_violation"
	}
	p.RenderSuccess(resp)
}

func (p *JSONPresenter) RenderMessage(msg string) {
	// Messages are usually suppressed in JSON mode or wrapped
}

// CLIPresenter renders results for human consumption.
type CLIPresenter struct {
	Stdout io.Writer
	Stderr io.Writer
}

func (p *CLIPresenter) RenderSuccess(result any) {
	// Basic implementation, can be specialized per result type
	if res, ok := result.(string); ok {
		fmt.Fprintln(p.Stdout, res)
	}
}

func (p *CLIPresenter) RenderError(err error) {
	fmt.Fprintf(p.Stderr, "Error: %v\n", err)
}

func (p *CLIPresenter) RenderMessage(msg string) {
	fmt.Fprintln(p.Stdout, msg)
}

// GetPresenter returns the appropriate presenter based on current mode.
func (h *UIHandler) GetPresenter() Presenter {
	if h.JSON {
		w := GlobalContext.JSONWriter
		if w == nil {
			w = JSONWriter
		}
		if w == nil {
			w = h.Stdout
		}
		return &JSONPresenter{Writer: w}
	}
	return &CLIPresenter{Stdout: h.Stdout, Stderr: h.Stderr}
}

func NewUIHandler() *UIHandler {
	return &UIHandler{
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Interactive: term.IsTerminal(int(os.Stdout.Fd())),
		JSON:        JSONOutput,
	}
}

// SecurePrint prints sensitive information only if the UI is interactive (or explicitly forced).
func (h *UIHandler) SecurePrint(secret string) {
	if h.JSON {
		return // Handled by printJSON
	}

	if h.Interactive {
		fmt.Fprintln(h.Stdout, secret)
	} else {
		fmt.Fprintln(h.Stderr, "⚠️  Warning: Sensitive output suppressed because stdout is not a terminal.")
		fmt.Fprintln(h.Stderr, "   Use --json for machine-readable output or redirect with care.")
	}
}

// SecurePrintf is the formatted version of SecurePrint.
func (h *UIHandler) SecurePrintf(format string, args ...any) {
	if h.JSON {
		return
	}

	if h.Interactive {
		fmt.Fprintf(h.Stdout, format, args...)
	} else {
		fmt.Fprintln(h.Stderr, "⚠️  Warning: Sensitive output suppressed because stdout is not a terminal.")
	}
}

// JSONOutput is a global flag for JSON formatting (legacy compatibility).
var JSONOutput bool
var JSONWriter io.Writer = os.Stdout

// SetJSONOutput toggles JSON mode globally.
func SetJSONOutput(enabled bool) {
	JSONOutput = enabled
	GlobalContext.JSONOutput = enabled
	if GlobalContext.UI != nil {
		GlobalContext.UI.JSON = enabled
	}
}

// SetupViper initializes the global Viper instance with Maknoon defaults and bindings.
func SetupViper() {
	viper.SetEnvPrefix("MAKNOON")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Bind env vars for backward compatibility/CI
	_ = viper.BindEnv("desec_token", "DESEC_TOKEN")
}

// Legacy global helpers redirected to the UI handler
func SecurePrint(secret string) {
	GlobalContext.UI.SecurePrint(secret)
}

func SecurePrintf(format string, args ...any) {
	GlobalContext.UI.SecurePrintf(format, args...)
}

// getPIN prompts the user for a FIDO2 PIN if not provided via environment or in agent mode.
func getPIN() (string, error) {
	if env := viper.GetString("fido2_pin"); env != "" {
		return env, nil
	}
	if GlobalContext.Engine != nil && GlobalContext.Engine.GetPolicy().IsAgent() {
		return "", nil // Library will handle the "PIN required" error if needed
	}

	fmt.Print("Enter FIDO2 Security Key PIN: ")
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(p), nil
}

// getPassphrase prompts the user for a passphrase if not provided and not in agent mode.
func getPassphrase(prompt string) ([]byte, bool, error) {
	if env := viper.GetString("passphrase"); env != "" {
		return []byte(env), false, nil
	}
	if GlobalContext.Engine != nil && GlobalContext.Engine.GetPolicy().IsAgent() {
		return nil, false, fmt.Errorf("passphrase required via MAKNOON_PASSPHRASE (interaction prohibited in agent mode)")
	}

	if GlobalContext.UI.JSON || !GlobalContext.UI.Interactive {
		fmt.Fprintf(os.Stderr, "⚠️  WARNING: Command requested interactive passphrase in non-interactive mode. This will likely hang or fail.\n")
	}

	fmt.Print(prompt)
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, false, err
	}
	return p, true, nil
}

// handleEngineEvents consumes the telemetry stream and updates the UI.
func handleEngineEvents(events <-chan crypto.EngineEvent, quiet bool) {
	// Never show status in JSON or Agent mode, or if explicitly quiet
	if quiet || GlobalContext.UI.JSON || viper.GetString("agent_mode") == "1" {
		for range events {
			// Drain events
		}
		return
	}

	for ev := range events {
		switch e := ev.(type) {
		case crypto.EventEncryptionStarted:
			if e.TotalBytes > 0 {
				fmt.Fprintf(os.Stderr, "[*] Protecting: %s\n", formatBytes(e.TotalBytes))
			} else {
				fmt.Fprintln(os.Stderr, "[*] Protecting...")
			}
		case crypto.EventDecryptionStarted:
			if e.TotalBytes > 0 {
				fmt.Fprintf(os.Stderr, "[*] Unprotecting: %s\n", formatBytes(e.TotalBytes))
			} else {
				fmt.Fprintln(os.Stderr, "[*] Unprotecting...")
			}
		case crypto.EventChunkProcessed:
			// For CLI humans, we could print dots or just stay silent until completion
			// to avoid log flooding. Let's stay silent for chunks.
		}
	}
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// GetTLSConfig returns a standardized Post-Quantum TLS 1.3 configuration.
func GetTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
		},
	}
}

func printJSON(data interface{}) {
	w := GlobalContext.JSONWriter
	if w == nil {
		w = JSONWriter
	}
	_ = json.NewEncoder(w).Encode(data)
}

func printErrorJSON(err error) {
	resp := map[string]interface{}{
		"error": err.Error(),
	}

	var policyErr *crypto.ErrPolicyViolation
	var authErr *crypto.ErrAuthentication
	var cryptoErr *crypto.ErrCrypto
	var stateErr *crypto.ErrState

	if crypto.As(err, &policyErr) {
		resp["type"] = "security_policy_violation"
		resp["is_security_violation"] = true
		resp["path"] = policyErr.Path
		resp["code"] = 403
	} else if crypto.As(err, &authErr) {
		resp["type"] = "authentication_failed"
		resp["code"] = 401
	} else if crypto.As(err, &cryptoErr) {
		resp["type"] = "cryptographic_failure"
		resp["code"] = 500
	} else if crypto.As(err, &stateErr) {
		resp["type"] = "system_state_error"
		resp["code"] = 503
	}

	w := GlobalContext.JSONWriter
	if w == nil {
		w = JSONWriter
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// validatePath is a helper for CLI commands to check path safety.
func validatePath(path string) error {
	if GlobalContext.Engine == nil {
		return nil
	}
	return GlobalContext.Engine.GetPolicy().ValidatePath(path)
}

func resolveProfile(name string) (byte, error) {
	switch strings.ToLower(name) {
	case "nist", "pq":
		return 1, nil
	case "aes":
		return 2, nil
	case "conservative", "legacy":
		return 3, nil
	case "hardened":
		return 4, nil
	}

	// Handle numeric IDs (used in tests)
	if id, err := strconv.Atoi(name); err == nil && id > 0 && id < 256 {
		return byte(id), nil
	}

	// Check custom profiles in config
	conf := crypto.GetGlobalConfig()
	if p, ok := conf.Profiles[name]; ok {
		return p.ID(), nil
	}

	return 0, fmt.Errorf("unknown profile: %s", name)
}

func checkJSONMode(cmd *cobra.Command) {
	if JSONOutput || viper.GetString("json") == "1" || viper.GetBool("json") {
		SetJSONOutput(true)
		if cmd != nil {
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
		}
	}
}

// Shell Completion Helpers

func completeIdentities(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	m := crypto.NewIdentityManager()
	ids, err := m.ListActiveIdentities()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	var results []string
	for _, id := range ids {
		if strings.HasPrefix(id, toComplete) {
			results = append(results, id)
		}
	}
	return results, cobra.ShellCompDirectiveNoFileComp
}

func completeVaults(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	conf := crypto.GetGlobalConfig()
	files, err := os.ReadDir(conf.Paths.VaultsDir)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	var results []string
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".vault") {
			name := strings.TrimSuffix(f.Name(), ".vault")
			if strings.HasPrefix(name, toComplete) {
				results = append(results, name)
			}
		}
	}
	return results, cobra.ShellCompDirectiveNoFileComp
}

func completeServices(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// Service names are now hashed for privacy in V1.4.
	// Autocomplete is disabled to prevent leaking service presence without the vault passphrase.
	return nil, cobra.ShellCompDirectiveNoFileComp
}

func completeProfiles(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	builtIn := []string{"nist", "aes", "conservative", "pq", "legacy", "hardened"}
	conf := crypto.GetGlobalConfig()

	var results []string
	for _, p := range builtIn {
		if strings.HasPrefix(p, toComplete) {
			results = append(results, p)
		}
	}
	for name := range conf.Profiles {
		if strings.HasPrefix(name, toComplete) {
			results = append(results, name)
		}
	}
	return results, cobra.ShellCompDirectiveNoFileComp
}

// LoadPrivateKey resolves and loads a private key with full FIDO2 support.
func LoadPrivateKey(path, envVar string, passphrase []byte) ([]byte, error) {
	resolvedPath := GlobalContext.Engine.ResolveKeyPath(nil, path, envVar)
	if resolvedPath == "" {
		return nil, fmt.Errorf("private key required (use flag or %s)", envVar)
	}

	var pin string
	if _, err := os.Stat(strings.TrimSuffix(resolvedPath, ".key") + ".fido2"); err == nil {
		var err2 error
		pin, err2 = getPIN()
		if err2 != nil {
			return nil, err2
		}
	}

	return GlobalContext.Engine.LoadPrivateKey(nil, resolvedPath, passphrase, pin, false)
}

// ResetGlobalContext clears all global state. Used primarily for tests.
func ResetGlobalContext() {
	crypto.ResetGlobalConfig()
	GlobalContext.Engine = nil
}

// InitEngine initializes the GlobalContext's Engine with the appropriate policy and audit logging.
func InitEngine() error {
	if GlobalContext.Engine != nil {
		_ = GlobalContext.Engine.Close()
	}

	SetupViper()
	crypto.ResetGlobalConfig()
	if err := crypto.EnsureMaknoonDirs(); err != nil {
		return err
	}
	var policy crypto.SecurityPolicy

	// Initialize UI Handler if not already present
	if GlobalContext.UI == nil {
		GlobalContext.UI = NewUIHandler()
	}

	// Only enable AgentPolicy if explicitly requested via environment variable.
	isAgent := viper.GetString("agent_mode") == "1"

	if isAgent || viper.GetBool("json") {
		SetJSONOutput(true)
	}

	if isAgent {
		policy = &crypto.AgentPolicy{}
	} else {
		policy = &crypto.HumanPolicy{}
	}

	// 2. Initialize Engine with DI
	conf := crypto.GetGlobalConfig()
	var engineLogger *slog.Logger = slog.Default()

	if viper.GetBool("trace") {
		handler := slog.NewTextHandler(GlobalContext.UI.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				// Industrial-grade redaction for sensitive fields
				key := strings.ToLower(a.Key)
				if strings.Contains(key, "pass") || strings.Contains(key, "secret") || strings.Contains(key, "key") || strings.Contains(key, "token") {
					return slog.String(a.Key, "[REDACTED]")
				}
				return a
			},
		})
		engineLogger = slog.New(handler)
		slog.SetDefault(engineLogger)

		// Redact sensitive flags from args before logging
		safeArgs := make([]string, len(os.Args))
		copy(safeArgs, os.Args)
		for i, arg := range safeArgs {
			if i > 0 {
				prev := strings.ToLower(safeArgs[i-1])
				if strings.Contains(prev, "pass") || strings.Contains(prev, "secret") || strings.Contains(prev, "key") {
					safeArgs[i] = "[REDACTED]"
				}
			}
			// Also check for --flag=value format
			if strings.Contains(arg, "=") {
				parts := strings.SplitN(arg, "=", 2)
				key := strings.ToLower(parts[0])
				if strings.Contains(key, "pass") || strings.Contains(key, "secret") || strings.Contains(key, "key") {
					safeArgs[i] = parts[0] + "=[REDACTED]"
				}
			}
		}

		slog.Debug("Maknoon Engine initializing", "version", "v1.3.x", "args", safeArgs)
		slog.Debug("Paths resolved", "home", crypto.GetUserHomeDir(), "keys", conf.Paths.KeysDir, "vaults", conf.Paths.VaultsDir)
	}

	idMgr := crypto.NewIdentityManager()
	core, err := crypto.NewEngine(policy, idMgr, conf, nil, engineLogger)
	if err != nil {
		return err
	}

	// Setup Audit Logging
	var auditLogger crypto.AuditLogger = &crypto.ConsoleAuditLogger{Writer: GlobalContext.UI.Stderr}
	if !viper.GetBool("verbose") && core.Config.Audit.Enabled {
		// Use file logger if enabled and not in verbose console mode
		l, err := crypto.NewJSONFileLogger(core.Config.Audit.LogFile)
		if err == nil {
			auditLogger = l
		}
	}

	GlobalContext.Engine = &crypto.AuditEngine{
		Engine: core,
		Logger: auditLogger,
	}

	return nil
}
