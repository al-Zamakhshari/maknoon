package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
)

func TestVaultGet(t *testing.T) {
	SetJSONOutput(false)
	vaultName := "testvault_get"
	passphrase := "testpass"

	// Clean up
	home := crypto.GetUserHomeDir()
	dbPath := filepath.Join(home, crypto.MaknoonDir, crypto.VaultsDir, vaultName+".vault")
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	// Set a secret first
	if err := os.Setenv("MAKNOON_PASSWORD", "token123"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("MAKNOON_PASSWORD")

	setCmd := VaultCmd()
	setCmd.SetArgs([]string{"--vault", vaultName, "--passphrase", passphrase, "set", "github", "--overwrite"})
	if err := setCmd.Execute(); err != nil {
		t.Fatal(err)
	}

	t.Run("Get existing service", func(t *testing.T) {
		getCmd := VaultCmd()
		getCmd.SetArgs([]string{"--vault", vaultName, "--passphrase", passphrase, "get", "github"})
		output := CaptureOutput(func() {
			if err := getCmd.Execute(); err != nil {
				t.Error(err)
			}
		})
		if !strings.Contains(output, "github") || !strings.Contains(output, "token123") {
			t.Errorf("Vault get failed. Output: %s", output)
		}
	})
	t.Run("Get missing service", func(t *testing.T) {
		getCmd := VaultCmd()
		getCmd.SetArgs([]string{"--vault", vaultName, "--passphrase", passphrase, "get", "missing"})

		output := CaptureOutput(func() {
			_ = getCmd.Execute()
		})

		if !strings.Contains(output, "not found") {
			t.Errorf("Expected error for missing service in output, got: %s", output)
		}
	})
}

func TestVaultList(t *testing.T) {
	SetJSONOutput(false)
	vaultName := "testvault_list_v2"
	passphrase := "testpass"

	// Clean up
	home := crypto.GetUserHomeDir()
	dbPath := filepath.Join(home, crypto.MaknoonDir, crypto.VaultsDir, vaultName+".vault")
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)
	setCmd := VaultCmd()
	if err := os.Setenv("MAKNOON_PASSWORD", "p1"); err != nil {
		t.Fatal(err)
	}
	setCmd.SetArgs([]string{"--vault", vaultName, "--passphrase", passphrase, "set", "svc1", "--overwrite"})
	if err := setCmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv("MAKNOON_PASSWORD", "p2"); err != nil {
		t.Fatal(err)
	}
	setCmd = VaultCmd()
	setCmd.SetArgs([]string{"--vault", vaultName, "--passphrase", passphrase, "set", "svc2", "--overwrite"})
	if err := setCmd.Execute(); err != nil {
		t.Fatal(err)
	}

	os.Unsetenv("MAKNOON_PASSWORD")

	listCmd := VaultCmd()
	listCmd.SetArgs([]string{"--vault", vaultName, "--passphrase", passphrase, "list"})
	output := CaptureOutput(func() {
		if err := listCmd.Execute(); err != nil {
			t.Error(err)
		}
	})

	if !strings.Contains(output, "svc1") || !strings.Contains(output, "svc2") {
		t.Errorf("Vault list missing services. Output: %s", output)
	}
}

func TestVaultJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Set custom home to ensure we are in a "safe" default vaults directory
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)
	_ = InitEngine()

	// Create the vaults dir
	vaultsDir := filepath.Join(tmpDir, ".maknoon", "vaults")
	if err := os.MkdirAll(vaultsDir, 0700); err != nil {
		t.Fatal(err)
	}

	vaultName := "testvault_json_v2"
	passphrase := "testpass"

	// Clean up
	home := crypto.GetUserHomeDir()
	dbPath := filepath.Join(home, crypto.MaknoonDir, crypto.VaultsDir, vaultName+".vault")
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	resetVaultGlobals := func() {
		SetJSONOutput(false)
		if err := os.Unsetenv("MAKNOON_JSON"); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Test triggering via ENVIRONMENT VARIABLE
	t.Run("Trigger via MAKNOON_JSON=1", func(t *testing.T) {
		resetVaultGlobals()
		if err := os.Setenv("MAKNOON_JSON", "1"); err != nil {
			t.Fatal(err)
		}
		// Manually sync since main.go isn't running
		SetJSONOutput(true)
		if err := os.Setenv("MAKNOON_PASSWORD", "pass1"); err != nil {
			t.Fatal(err)
		}
		defer os.Unsetenv("MAKNOON_PASSWORD")

		setCmd := VaultCmd()
		setCmd.SetArgs([]string{"--vault", vaultName, "--passphrase", passphrase, "set", "service_env"})

		output := CaptureOutput(func() {
			_ = setCmd.Execute()
		})

		if !strings.Contains(output, `"status": "success"`) || !strings.Contains(output, `"service": "service_env"`) {
			t.Errorf("Env var trigger failed. Output: %s", output)
		}
	})

	// 2. Test triggering via FLAG
	t.Run("Trigger via --json flag", func(t *testing.T) {
		resetVaultGlobals()
		// Manually sync since main.go isn't running
		SetJSONOutput(true)
		getCmd := VaultCmd()
		getCmd.SetArgs([]string{"--vault", vaultName, "--passphrase", passphrase, "get", "service_env", "--json"})

		output := CaptureOutput(func() {
			_ = getCmd.Execute()
		})

		if !strings.Contains(output, `"password": "pass1"`) {
			t.Errorf("Flag trigger failed. Output: %s", output)
		}

	})

	// 3. Test Error Output in JSON mode
	t.Run("JSON Error formatting", func(t *testing.T) {
		resetVaultGlobals()
		if err := os.Setenv("MAKNOON_JSON", "1"); err != nil {
			t.Fatal(err)
		}
		// Manually sync since main.go isn't running
		SetJSONOutput(true)
		getCmdErr := VaultCmd()
		getCmdErr.SetArgs([]string{"--vault", vaultName, "--passphrase", passphrase, "get", "nonexistent"})

		output := CaptureOutput(func() {
			_ = getCmdErr.Execute() // Expected to fail
		})

		if !strings.Contains(output, `"error":`) || !strings.Contains(output, "not found") {
			t.Errorf("Error JSON formatting failed. Output: %s", output)
		}
	})
}
