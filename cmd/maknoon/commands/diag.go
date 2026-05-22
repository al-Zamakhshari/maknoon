package commands

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// DiagCmd returns the machine-readable engine state manifest command.
func DiagCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diag",
		Short: "Output a machine-readable engine state manifest",
		Long:  "Generates a JSON manifest containing system information, filesystem paths, active security policies, and cryptographic defaults.",
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			res := GlobalContext.Engine.Diagnostic()
			p.RenderSuccess(res)
			return nil
		},
	}
	return cmd
}

// CheckResult is a single health-check outcome.
type CheckResult struct {
	Status  string `json:"status"` // "ok", "warning", "error"
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// DoctorReport holds results for all health checks.
type DoctorReport struct {
	KeysDir    CheckResult `json:"keys_dir"`
	VaultsDir  CheckResult `json:"vaults_dir"`
	Identities CheckResult `json:"identities"`
	DefaultID  CheckResult `json:"default_identity"`
	Vaults     CheckResult `json:"vaults"`
	Config     CheckResult `json:"config"`
	Audit      CheckResult `json:"audit"`
	TPM        CheckResult `json:"tpm"`
	Entropy    CheckResult `json:"entropy"`
}

// Healthy returns true when no check has status "error".
func (r *DoctorReport) Healthy() bool {
	for _, c := range []CheckResult{
		r.KeysDir, r.VaultsDir, r.Identities, r.DefaultID,
		r.Vaults, r.Config, r.Audit, r.TPM, r.Entropy,
	} {
		if c.Status == "error" {
			return false
		}
	}
	return true
}

// DoctorCmd returns the comprehensive health-check command.
func DoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Comprehensive system health check",
		Long: `Checks your Maknoon environment and reports the status of each component:

  keys directory, vaults directory, active identities, default identity,
  vault accessibility, config validity, audit logging, TPM availability,
  and cryptographic entropy.

Use --json for machine-readable output (suitable for CI and MCP agents).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			report := runDoctor()
			if GlobalContext.UI.JSON {
				GlobalContext.UI.GetPresenter().RenderSuccess(report)
			} else {
				printDoctorReport(report)
			}
			if !report.Healthy() {
				return fmt.Errorf("one or more checks failed — review the report above")
			}
			return nil
		},
	}
	return cmd
}

func runDoctor() *DoctorReport {
	conf := crypto.GetGlobalConfig()
	r := &DoctorReport{}

	// 1. Keys directory
	r.KeysDir = checkDir(conf.Paths.KeysDir, "Keys directory", true)

	// 2. Vaults directory
	r.VaultsDir = checkDir(conf.Paths.VaultsDir, "Vaults directory", false)

	// 3. Active identities
	ids, err := GlobalContext.Engine.IdentityActive(nil)
	if err != nil || len(ids) == 0 {
		r.Identities = CheckResult{Status: "warning", Message: "No identities found",
			Detail: "run 'maknoon keygen' or 'maknoon init' to create one"}
	} else {
		r.Identities = CheckResult{Status: "ok",
			Message: fmt.Sprintf("%d identity/identities present", len(ids)),
			Detail:  strings.Join(ids, ", ")}
	}

	// 4. Default identity
	defID := conf.DefaultIdentity
	found := false
	for _, id := range ids {
		if id == defID {
			found = true
			break
		}
	}
	if found {
		r.DefaultID = CheckResult{Status: "ok", Message: fmt.Sprintf("Default identity '%s' found", defID)}
	} else {
		r.DefaultID = CheckResult{Status: "warning",
			Message: fmt.Sprintf("Default identity '%s' not found", defID),
			Detail:  "run 'maknoon config set default_identity <name>' to point to an existing identity"}
	}

	// 5. Vaults
	entries, err := os.ReadDir(conf.Paths.VaultsDir)
	vaultCount := 0
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".vault") {
				vaultCount++
			}
		}
	}
	if vaultCount > 0 {
		r.Vaults = CheckResult{Status: "ok", Message: fmt.Sprintf("%d vault file(s) found", vaultCount)}
	} else {
		r.Vaults = CheckResult{Status: "warning", Message: "No vault files found",
			Detail: "run 'maknoon init' or 'maknoon vault set' to create one"}
	}

	// 6. Config validity
	if err := conf.Validate(); err != nil {
		r.Config = CheckResult{Status: "error", Message: "Configuration invalid", Detail: err.Error()}
	} else {
		r.Config = CheckResult{Status: "ok", Message: "Configuration valid"}
	}

	// 7. Audit logging
	if conf.Audit.Enabled {
		logDir := filepath.Dir(conf.Audit.LogFile)
		if err := os.MkdirAll(logDir, 0700); err != nil {
			r.Audit = CheckResult{Status: "warning", Message: "Audit enabled but log directory not writable",
				Detail: err.Error()}
		} else {
			r.Audit = CheckResult{Status: "ok", Message: "Audit logging enabled",
				Detail: conf.Audit.LogFile}
		}
	} else {
		r.Audit = CheckResult{Status: "warning", Message: "Audit logging disabled",
			Detail: "enable with 'maknoon config set audit.enabled true'"}
	}

	// 8. TPM
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/dev/tpmrm0"); err == nil {
			r.TPM = CheckResult{Status: "ok", Message: "TPM 2.0 device available at /dev/tpmrm0"}
		} else {
			r.TPM = CheckResult{Status: "warning", Message: "TPM 2.0 not available (optional)",
				Detail: "use 'maknoon --tpm' flags to enable hardware-backed key storage"}
		}
	} else {
		r.TPM = CheckResult{Status: "ok",
			Message: fmt.Sprintf("TPM check skipped on %s (Linux-only)", runtime.GOOS)}
	}

	// 9. Entropy
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		r.Entropy = CheckResult{Status: "error", Message: "Cryptographic entropy unavailable",
			Detail: err.Error()}
	} else {
		r.Entropy = CheckResult{Status: "ok", Message: "Cryptographic entropy OK (32 bytes sampled)"}
	}

	return r
}

func checkDir(path, label string, requireMode bool) CheckResult {
	info, err := os.Stat(path)
	if err != nil {
		return CheckResult{Status: "warning",
			Message: fmt.Sprintf("%s missing at %s", label, path),
			Detail:  "run 'maknoon init' to create it"}
	}
	if requireMode && info.Mode().Perm()&0o077 != 0 {
		return CheckResult{Status: "warning",
			Message: fmt.Sprintf("%s has loose permissions (%s)", label, info.Mode().Perm()),
			Detail:  fmt.Sprintf("run: chmod 700 %s", path)}
	}
	return CheckResult{Status: "ok", Message: fmt.Sprintf("%s ready", label), Detail: path}
}

func printDoctorReport(r *DoctorReport) {
	checks := []struct {
		label  string
		result CheckResult
	}{
		{"Keys directory  ", r.KeysDir},
		{"Vaults directory", r.VaultsDir},
		{"Identities     ", r.Identities},
		{"Default identity", r.DefaultID},
		{"Vault files    ", r.Vaults},
		{"Configuration  ", r.Config},
		{"Audit logging  ", r.Audit},
		{"TPM 2.0        ", r.TPM},
		{"Entropy        ", r.Entropy},
	}

	fmt.Fprintln(os.Stderr, "\nMaknoon System Health")
	fmt.Fprintln(os.Stderr, "═══════════════════════════════════════════════════════")
	for _, c := range checks {
		var sym string
		switch c.result.Status {
		case "ok":
			sym = icon("✓", "ok  ")
		case "warning":
			sym = icon("⚠️ ", "WARN")
		default:
			sym = icon("✗", "ERR ")
		}
		line := fmt.Sprintf("  %s  %-18s %s", sym, c.label, c.result.Message)
		if c.result.Detail != "" && c.result.Status != "ok" {
			line += fmt.Sprintf("\n         └─ %s", c.result.Detail)
		}
		fmt.Fprintln(os.Stderr, line)
	}
	fmt.Fprintln(os.Stderr, "═══════════════════════════════════════════════════════")

	if r.Healthy() {
		fmt.Fprintln(os.Stderr, icon("✅", "ALL GOOD")+" System ready.")
	} else {
		fmt.Fprintln(os.Stderr, icon("⚠️ ", "WARNING:")+" Review items above before use.")
	}

	// JSON hint
	raw, _ := json.Marshal(r)
	_ = raw
}
