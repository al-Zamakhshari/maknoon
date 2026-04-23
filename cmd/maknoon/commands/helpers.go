package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// getPIN prompts the user for a FIDO2 PIN if not provided via environment or in agent mode.
func getPIN() (string, error) {
	if env := os.Getenv("MAKNOON_FIDO2_PIN"); env != "" {
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
// It returns the passphrase and a boolean indicating if it was collected via terminal interaction.
func getPassphrase(prompt string) ([]byte, bool, error) {
	if env := os.Getenv("MAKNOON_PASSPHRASE"); env != "" {
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
				_ = bar.Set64(e.TotalProcessed)
			}
		case crypto.EventHandshakeComplete:
			// Handshake done, usually fast so maybe just a log if verbose
		}
	}
	if bar != nil {
		_ = bar.Finish()
		fmt.Fprintln(os.Stderr)
	}
}

// Context encapsulates the execution state of the Maknoon CLI.
type Context struct {
	JSONOutput bool
	JSONWriter io.Writer
	Engine     crypto.MaknoonEngine
}

// GlobalContext is the default context for CLI execution.
var GlobalContext = &Context{
	JSONWriter: os.Stdout,
}

// printJSON outputs an interface as a JSON string to the context's writer.
func (c *Context) printJSON(v interface{}) {
	raw, _ := json.Marshal(v)
	fmt.Fprintln(c.JSONWriter, string(raw))
}

// printErrorJSON outputs an error as a JSON object to stderr, including metadata for typed errors.
func (c *Context) printErrorJSON(err error) {
	resp := map[string]interface{}{
		"error": err.Error(),
	}

	// Inspect typed errors for metadata
	var policyErr *crypto.ErrPolicyViolation
	var authErr *crypto.ErrAuthentication
	var cryptoErr *crypto.ErrCrypto
	var stateErr *crypto.ErrState

	if crypto.As(err, &policyErr) {
		resp["type"] = "security_policy_violation"
		resp["is_security_violation"] = true
		resp["code"] = 403
		if policyErr.Path != "" {
			resp["path"] = policyErr.Path
		}
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

	raw, _ := json.Marshal(resp)
	fmt.Fprintln(os.Stderr, string(raw))
}

// printJSON outputs an interface using the GlobalContext.
func printJSON(v interface{}) {
	GlobalContext.printJSON(v)
}

// printErrorJSON outputs an error using the GlobalContext.
func printErrorJSON(err error) {
	GlobalContext.printErrorJSON(err)
}

// JSONOutput is kept as a global shim for now, but will be phased out.
var JSONOutput bool = false

// JSONWriter is kept as a global shim for now.
var JSONWriter io.Writer = os.Stdout

// resolveKeyPath checks if a key exists locally, in ~/.maknoon/keys/, or in environment variables.
func resolveKeyPath(path string, envVar string) string {
	return crypto.ResolveKeyPath(path, envVar)
}

// SetJSONOutput enables or disables JSON mode across the application.
func SetJSONOutput(enabled bool) {
	JSONOutput = enabled
	GlobalContext.JSONOutput = enabled
}

// InitEngine initializes the GlobalContext's Engine with the appropriate policy and audit logging.
func InitEngine() error {
	crypto.ResetGlobalConfig()
	var policy crypto.SecurityPolicy
	isAgent := crypto.IsAgentMode() || JSONOutput

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
		l, err := crypto.NewJSONFileLogger(core.Config.Audit.LogFile)
		if err == nil {
			logger = l
		}
	}

	GlobalContext.Engine = &crypto.AuditEngine{
		Engine: core,
		Logger: logger,
	}

	return nil
}

// resolveProfile maps a profile name or ID string to a byte ID.
func resolveProfile(p string) (byte, error) {
	switch p {
	case "1", "nist", "pq":
		return 1, nil
	case "2", "aes", "legacy":
		return 2, nil
	case "3", "conservative", "hardened":
		return 3, nil
	}

	// Check config for custom profile name
	if dp, ok := crypto.GetGlobalConfig().Profiles[p]; ok {
		return dp.ID(), nil
	}

	// Attempt to parse as direct ID
	var id byte
	if _, err := fmt.Sscanf(p, "%d", &id); err == nil {
		return id, nil
	}
	return 0, fmt.Errorf("unknown profile: %s (supported: nist, aes, conservative, or custom name in config)", p)
}

// validatePath ensures a path is safe to use.
func validatePath(path string) error {
	if GlobalContext.Engine == nil {
		return nil
	}
	return GlobalContext.Engine.GetPolicy().ValidatePath(path)
}

func checkJSONMode(cmd *cobra.Command) {
	if JSONOutput || os.Getenv("MAKNOON_JSON") == "1" {
		JSONOutput = true
		if cmd != nil {
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
		}
	}
}
