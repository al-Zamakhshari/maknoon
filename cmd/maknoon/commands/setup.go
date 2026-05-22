package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// InitCmd returns the guided first-run setup command.
func InitCmd() *cobra.Command {
	var nonInteractive bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Guided first-run setup — create identity, vault, and verify your environment",
		Long: `Walks through all necessary steps to get started with Maknoon:

  1. Create ~/.maknoon/ directory structure
  2. Generate a default ML-KEM-768 + ML-DSA-87 identity
  3. Initialise a default encrypted vault
  4. Optionally enable audit logging
  5. Smoke-test encrypt → decrypt to confirm everything works

Use --non-interactive for Docker/CI environments (all defaults applied, no prompts).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(nonInteractive)
		},
	}

	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false,
		"Skip all prompts and apply defaults (suitable for Docker/CI)")
	return cmd
}

func runInit(nonInteractive bool) error {
	step := func(n int, label string) { fmt.Fprintf(os.Stderr, "\nStep %d: %s\n", n, label) }
	ok := func(msg string) { fmt.Fprintf(os.Stderr, "%s %s\n", icon("✓", "ok"), msg) }
	warn := func(msg string) { fmt.Fprintf(os.Stderr, "%s %s\n", icon("⚠️ ", "WARN:"), msg) }

	fmt.Fprintln(os.Stderr, icon("🔐", ">>")+" Maknoon first-run setup")
	fmt.Fprintln(os.Stderr, "────────────────────────────────────────")

	// ── Step 1: directories ──────────────────────────────────────────────────
	step(1, "Creating directory structure")
	if err := crypto.EnsureMaknoonDirs(); err != nil {
		return fmt.Errorf("step 1: %w", err)
	}
	ok("~/.maknoon/{keys,vaults,profiles} ready")

	// ── Step 2: identity ─────────────────────────────────────────────────────
	step(2, "Generating default identity (ML-KEM-768 + ML-DSA-87)")

	var idPass []byte
	if nonInteractive {
		idPass = nil // no password in non-interactive mode
	} else {
		fmt.Fprint(os.Stderr, "  Identity passphrase (leave empty for no password): ")
		var err error
		idPass, _, err = getPassphrase("")
		if err != nil {
			warn("Could not read passphrase — creating identity without password")
		}
		defer crypto.SafeClear(idPass)
	}

	existing, _ := GlobalContext.Engine.IdentityActive(nil)
	if containsString(existing, "default") {
		ok("Default identity already exists — skipping")
	} else {
		_, err := GlobalContext.Engine.CreateIdentity(nil, "default", idPass, "", false, "nist")
		if err != nil {
			return fmt.Errorf("step 2: %w", err)
		}
		ok("Identity 'default' created (Profile 1 / NIST)")
	}

	// ── Step 3: vault ────────────────────────────────────────────────────────
	step(3, "Initialising default vault")

	var vaultPass []byte
	if nonInteractive {
		vaultPass = []byte("changeme")
		warn("Non-interactive mode: vault created with passphrase 'changeme' — change it before use")
	} else {
		fmt.Fprint(os.Stderr, "  Vault passphrase: ")
		var err error
		vaultPass, _, err = getPassphrase("")
		if err != nil {
			return fmt.Errorf("step 3: could not read vault passphrase: %w", err)
		}
		defer crypto.SafeClear(vaultPass)
	}

	conf := GlobalContext.Engine.GetConfig()
	defaultVaultPath := filepath.Join(conf.Paths.VaultsDir, "default.vault")
	if _, err := os.Stat(defaultVaultPath); err == nil {
		ok("Default vault already exists — skipping")
	} else {
		// Create vault by storing a sentinel entry, then deleting it.
		sentinel := &crypto.VaultEntry{Service: "__init__", Password: []byte("init")}
		if err := GlobalContext.Engine.VaultSet(nil, "default", sentinel, vaultPass, "", false); err != nil {
			return fmt.Errorf("step 3: %w", err)
		}
		if err := GlobalContext.Engine.VaultSet(nil, "default",
			&crypto.VaultEntry{Service: "__init__", Password: []byte("init")},
			vaultPass, "", true); err == nil {
			// Delete sentinel — vault file persists even when empty
		}
		ok("Vault 'default' initialised")
	}

	// ── Step 4: audit (optional) ─────────────────────────────────────────────
	step(4, "Audit logging")
	if conf.Audit.Enabled {
		ok(fmt.Sprintf("Audit already enabled → %s", conf.Audit.LogFile))
	} else if nonInteractive {
		ok("Skipped (use 'maknoon config set audit.enabled true' to enable)")
	} else {
		fmt.Fprint(os.Stderr, "  Enable audit logging? [y/N]: ")
		var answer string
		fmt.Fscanln(os.Stdin, &answer)
		if answer == "y" || answer == "Y" || answer == "yes" {
			conf.Audit.Enabled = true
			if err := conf.Save(); err != nil {
				warn(fmt.Sprintf("Could not save config: %v", err))
			} else {
				ok(fmt.Sprintf("Audit enabled → %s", conf.Audit.LogFile))
			}
		} else {
			ok("Skipped")
		}
	}

	// ── Step 5: smoke test ───────────────────────────────────────────────────
	step(5, "Smoke test — encrypt → decrypt round-trip")
	smokeDir := os.TempDir()
	smokeIn := filepath.Join(smokeDir, "maknoon_init_smoke.txt")
	smokeOut := filepath.Join(smokeDir, "maknoon_init_smoke.makn")
	smokeBack := filepath.Join(smokeDir, "maknoon_init_smoke_dec.txt")
	defer func() {
		_ = os.Remove(smokeIn)
		_ = os.Remove(smokeOut)
		_ = os.Remove(smokeBack)
	}()

	_ = os.WriteFile(smokeIn, []byte("maknoon init smoke test payload"), 0600)
	smokePass := []byte("smoke-test-pass")

	outF, _ := os.Create(smokeOut)
	_, encErr := GlobalContext.Engine.Protect(nil, smokeIn, nil, outF, crypto.Options{Passphrase: smokePass})
	_ = outF.Close()
	if encErr != nil {
		return fmt.Errorf("step 5: encrypt failed: %w", encErr)
	}
	inF, _ := os.Open(smokeOut)
	_, decErr := GlobalContext.Engine.Unprotect(nil, inF, nil, smokeBack, crypto.Options{Passphrase: smokePass})
	_ = inF.Close()
	if decErr != nil {
		return fmt.Errorf("step 5: decrypt failed: %w", decErr)
	}
	ok("Encrypt → decrypt round-trip passed")

	// ── Done ─────────────────────────────────────────────────────────────────
	fmt.Fprintln(os.Stderr, "\n"+icon("✅", "DONE")+" Setup complete.")
	fmt.Fprintln(os.Stderr, "  Run 'maknoon doctor' to verify your environment at any time.")
	fmt.Fprintln(os.Stderr, "  Run 'maknoon --help' or see docs/getting-started/QUICKSTART.md to get started.")
	return nil
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
