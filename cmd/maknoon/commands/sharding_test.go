package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultShardingCLI(t *testing.T) {
	SetJSONOutput(false)
	tmpDir := t.TempDir()

	// Set custom home
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)
	_ = InitEngine()

	vaultsDir := filepath.Join(tmpDir, ".maknoon", "vaults")
	os.MkdirAll(vaultsDir, 0700)

	vaultName := "testshardvault"
	pass := "vaultpass"

	// 1. Set a secret
	os.Setenv("MAKNOON_PASSWORD", "secret123")
	defer os.Unsetenv("MAKNOON_PASSWORD")
	setCmd := VaultCmd()
	setCmd.SetArgs([]string{"-v", vaultName, "-s", pass, "set", "svc1"})
	if err := setCmd.Execute(); err != nil {
		t.Fatalf("Vault set failed: %v", err)
	}

	// 2. Split vault
	splitCmd := VaultCmd()
	splitCmd.SetArgs([]string{"-v", vaultName, "-s", pass, "split"})

	SetJSONOutput(true)
	output := CaptureOutput(func() {
		if err := splitCmd.Execute(); err != nil {
			t.Errorf("Vault split failed: %v", err)
		}
	})
	SetJSONOutput(false)

	if !strings.Contains(output, "shares") {
		t.Errorf("Expected shares in vault split output, got: %s", output)
	}
}
