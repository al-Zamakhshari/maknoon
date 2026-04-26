package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/schollz/progressbar/v3"
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

// NewUIHandler creates a default UI handler based on the current environment.
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

	fmt.Print(prompt)
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, false, err
	}
	return p, true, nil
}

// handleEngineEvents consumes the telemetry stream and updates the UI (e.g., progress bars).
func handleEngineEvents(events <-chan crypto.EngineEvent, quiet bool) {
	var bar *progressbar.ProgressBar
	for ev := range events {
		if quiet {
			continue
		}
		switch e := ev.(type) {
		case crypto.EventEncryptionStarted:
			if e.TotalBytes > 0 {
				bar = progressbar.DefaultBytes(e.TotalBytes, "protecting")
			} else {
				fmt.Fprintln(os.Stderr, "Protecting...")
			}
		case crypto.EventDecryptionStarted:
			if e.TotalBytes > 0 {
				bar = progressbar.DefaultBytes(e.TotalBytes, "unprotecting")
			} else {
				fmt.Fprintln(os.Stderr, "Unprotecting...")
			}
		case crypto.EventChunkProcessed:
			if bar != nil {
				_ = bar.Add64(e.BytesProcessed)
			}
		}
	}
	if bar != nil {
		_ = bar.Finish()
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
	vaultName, _ := cmd.Flags().GetString("vault")
	if vaultName == "" {
		vaultName = "default"
	}

	conf := crypto.GetGlobalConfig()
	vaultPath := filepath.Join(conf.Paths.VaultsDir, vaultName+".vault")
	if _, err := os.Stat(vaultPath); err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	services, err := crypto.ListVaultEntries(vaultPath)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	var results []string
	for _, s := range services {
		if strings.HasPrefix(s, toComplete) {
			results = append(results, s)
		}
	}
	return results, cobra.ShellCompDirectiveNoFileComp
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

// InitEngine initializes the GlobalContext's Engine with the appropriate policy and audit logging.
func InitEngine() error {
	SetupViper()
	crypto.ResetGlobalConfig()
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

	core, err := crypto.NewEngine(policy)
	if err != nil {
		return err
	}

	// Setup Audit Logging
	var logger crypto.AuditLogger = &crypto.NoopLogger{}
	if core.Config.Audit.Enabled && !isAgent {
		// Only enable rich auditing in non-agent/human modes
		logger = crypto.NewJSONFileLogger(core.Config.Audit.LogFile)
	}

	GlobalContext.Engine = &crypto.AuditEngine{
		Engine: core,
		Logger: slog.Default(),
		Audit:  logger,
	}

	return nil
}
