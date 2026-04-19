// Package commands contains the implementation and tests for the Maknoon CLI commands.
package commands

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
)

func TestGenCmd(t *testing.T) {
	SetJSONOutput(false)
	t.Run("Default password", func(t *testing.T) {
		cmd := GenCmd()
		cmd.SetArgs([]string{"password"})
		output := CaptureOutput(func() {
			if err := cmd.Execute(); err != nil {
				t.Error(err)
			}
		})
		if len(strings.TrimSpace(output)) != 32 {
			t.Errorf("Expected default length 32, got %d", len(strings.TrimSpace(output)))
		}
	})

	t.Run("Custom length", func(t *testing.T) {
		cmd := GenCmd()
		cmd.SetArgs([]string{"password", "--length", "16"})
		output := CaptureOutput(func() {
			if err := cmd.Execute(); err != nil {
				t.Error(err)
			}
		})
		if len(strings.TrimSpace(output)) != 16 {
			t.Errorf("Expected length 16, got %d", len(strings.TrimSpace(output)))
		}
	})

	t.Run("Passphrase mode", func(t *testing.T) {
		cmd := GenCmd()
		cmd.SetArgs([]string{"passphrase", "--words", "5"})
		output := CaptureOutput(func() {
			if err := cmd.Execute(); err != nil {
				t.Error(err)
			}
		})
		words := strings.Split(strings.TrimSpace(output), "-")
		if len(words) != 5 {
			t.Errorf("Expected 5 words, got %d. Output: %s", len(words), output)
		}
	})
}

func TestResolveKeyPath(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "maknoon_key_*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// 1. Explicit path
	res := resolveKeyPath(tmpFile.Name(), "UNUSED")
	if res != tmpFile.Name() {
		t.Errorf("Expected %s, got %s", tmpFile.Name(), res)
	}

	// 2. Env var
	envKey := "MAKNOON_TEST_KEY_PATH"
	if err := os.Setenv(envKey, tmpFile.Name()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Unsetenv(envKey) }()
	res = resolveKeyPath("", envKey)
	if res != tmpFile.Name() {
		t.Errorf("Expected %s from env, got %s", tmpFile.Name(), res)
	}
}

func TestVaultGet(t *testing.T) {
	SetJSONOutput(false)
	vaultName := "testvault_get"
	passphrase := "testpass"

	// Clean up
	home, _ := os.UserHomeDir()
	dbPath := filepath.Join(home, crypto.MaknoonDir, crypto.VaultsDir, vaultName+".db")
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	// Set a secret first
	if err := os.Setenv("MAKNOON_PASSWORD", "token123"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("MAKNOON_PASSWORD")

	setCmd := VaultCmd()
	setCmd.SetArgs([]string{"--vault", vaultName, "--passphrase", passphrase, "set", "github"})
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
		getCmd.SetArgs([]string{"--vault", vaultName, "--passphrase", passphrase, "get", "nonexistent"})
		if err := getCmd.Execute(); err == nil {
			t.Error("Expected error for missing service, got nil")
		}
	})
}

func TestVaultList(t *testing.T) {
	SetJSONOutput(false)
	vaultName := "testvault_list_v2"
	passphrase := "testpass"

	// Clean up
	home, _ := os.UserHomeDir()
	dbPath := filepath.Join(home, crypto.MaknoonDir, crypto.VaultsDir, vaultName+".db")
	_ = os.Remove(dbPath)
	defer os.Remove(dbPath)

	setCmd := VaultCmd()
	if err := os.Setenv("MAKNOON_PASSWORD", "p1"); err != nil {
		t.Fatal(err)
	}
	setCmd.SetArgs([]string{"--vault", vaultName, "--passphrase", passphrase, "set", "svc1"})
	if err := setCmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv("MAKNOON_PASSWORD", "p2"); err != nil {
		t.Fatal(err)
	}
	setCmd.SetArgs([]string{"--vault", vaultName, "--passphrase", passphrase, "set", "svc2"})
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

func TestDecryptFailures(t *testing.T) {
	SetJSONOutput(false)
	tmpDir := t.TempDir()

	t.Run("File not found", func(t *testing.T) {
		dec := DecryptCmd()
		dec.SetArgs([]string{filepath.Join(tmpDir, "non-existent.makn")})
		if JSONOutput {
			_ = dec.Execute() // JSON error on stderr
		} else {
			if err := dec.Execute(); err == nil {
				t.Error("Expected error for non-existent file")
			}
		}
	})

	t.Run("Wrong passphrase", func(t *testing.T) {
		inputFile := filepath.Join(tmpDir, "secret.txt")
		if err := os.WriteFile(inputFile, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
		enc := EncryptCmd()
		enc.SetArgs([]string{inputFile, "-o", inputFile + ".makn", "-s", "right-pass", "--quiet"})
		if err := enc.Execute(); err != nil {
			t.Fatal(err)
		}

		dec := DecryptCmd()
		dec.SetArgs([]string{inputFile + ".makn", "-s", "wrong-pass", "--quiet"})

		if JSONOutput {
			_ = dec.Execute() // JSON error on stderr
		} else {
			if err := dec.Execute(); err == nil {
				t.Error("Expected decryption failure for wrong passphrase")
			}
		}
	})
}

func TestEncryptDecryptSymmetric(t *testing.T) {
	SetJSONOutput(false)
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.txt")
	content := []byte("Hello Maknoon Integration")
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	encryptedFile := inputFile + ".makn"
	decryptedFile := filepath.Join(tmpDir, "decrypted.txt")
	pass := "my-secret-key-123"

	enc := EncryptCmd()
	enc.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", pass, "--quiet"})
	if err := enc.Execute(); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	dec := DecryptCmd()
	dec.SetArgs([]string{encryptedFile, "-o", decryptedFile, "-s", pass, "--quiet"})
	if err := dec.Execute(); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	restored, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, restored) {
		t.Error("Restored content mismatch")
	}
}

func TestKeygenAndAsymmetric(t *testing.T) {
	SetJSONOutput(false)
	tmpDir := t.TempDir()
	keyBase := filepath.Join(tmpDir, "id_test")

	// 1. Generate keys
	gen := KeygenCmd()
	gen.SetArgs([]string{"-o", keyBase, "--no-password"})
	if err := gen.Execute(); err != nil {
		t.Fatalf("Keygen failed: %v", err)
	}

	// 2. Encrypt with public key
	inputFile := filepath.Join(tmpDir, "msg.txt")
	content := []byte("Post-Quantum Secret Message")
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatal(err)
	}
	encryptedFile := inputFile + ".makn"

	enc := EncryptCmd()
	enc.SetArgs([]string{inputFile, "-o", encryptedFile, "--public-key", keyBase + ".kem.pub", "--quiet"})
	if err := enc.Execute(); err != nil {
		t.Fatalf("Asymmetric encryption failed: %v", err)
	}

	// 3. Decrypt with private key
	decryptedFile := filepath.Join(tmpDir, "msg_restored.txt")
	dec := DecryptCmd()
	dec.SetArgs([]string{encryptedFile, "-o", decryptedFile, "--private-key", keyBase + ".kem.key", "--quiet"})
	if err := dec.Execute(); err != nil {
		t.Fatalf("Asymmetric decryption failed: %v", err)
	}

	restored, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, restored) {
		t.Error("Asymmetric restored content mismatch")
	}
}

func TestKeygenWithEnvPassphrase(t *testing.T) {
	SetJSONOutput(false)
	tmpDir := t.TempDir()
	keyBase := filepath.Join(tmpDir, "id_env_test")
	passphrase := "env-pass-123"

	if err := os.Setenv("MAKNOON_PASSPHRASE", passphrase); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Unsetenv("MAKNOON_PASSPHRASE") }()

	gen := KeygenCmd()
	gen.SetArgs([]string{"-o", keyBase})
	if err := gen.Execute(); err != nil {
		t.Fatalf("Keygen with env pass failed: %v", err)
	}
}

func TestVaultJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Set custom home to ensure we are in a "safe" default vaults directory
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)

	// Create the vaults dir
	vaultsDir := filepath.Join(tmpDir, ".maknoon", "vaults")
	if err := os.MkdirAll(vaultsDir, 0700); err != nil {
		t.Fatal(err)
	}

	vaultName := "testvault_json_v2"
	passphrase := "testpass"

	// Clean up
	home, _ := os.UserHomeDir()
	dbPath := filepath.Join(home, crypto.MaknoonDir, crypto.VaultsDir, vaultName+".db")
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
			if err := setCmd.Execute(); err != nil {
				t.Error(err)
			}
		})
		if !strings.Contains(output, `{"service":"service_env","status":"success"}`) {
			t.Errorf("Env var trigger failed. Output: %s", output)
		}
	})

	// 2. Test triggering via FLAG
	t.Run("Trigger via --json flag", func(t *testing.T) {
		resetVaultGlobals()
		// Manually sync since main.go isn't running
		SetJSONOutput(true)
		getCmd := VaultCmd()
		getCmd.SetArgs([]string{"--vault", vaultName, "--passphrase", passphrase, "--json", "get", "service_env"})
		output := CaptureOutput(func() {
			if err := getCmd.Execute(); err != nil {
				t.Error(err)
			}
		})
		if !strings.Contains(output, `"service":"service_env"`) {
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

		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w
		_ = getCmdErr.Execute() // Expected to fail, checking JSON error message on stderr
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		os.Stderr = oldStderr
		var errBuf bytes.Buffer
		if _, err := io.Copy(&errBuf, r); err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(errBuf.String(), `{"error":"service not found"}`) {
			t.Errorf("Error JSON formatting failed. Output: %s", errBuf.String())
		}
	})
}

func TestSignVerify(t *testing.T) {
	SetJSONOutput(false)
	tmpDir := t.TempDir()
	keyBase := filepath.Join(tmpDir, "sig_test")

	keygenCmd := KeygenCmd()
	keygenCmd.SetArgs([]string{"-o", keyBase, "--no-password"})
	if err := keygenCmd.Execute(); err != nil {
		t.Fatal(err)
	}

	msgFile := filepath.Join(tmpDir, "message.txt")
	if err := os.WriteFile(msgFile, []byte("Authentic message"), 0644); err != nil {
		t.Fatal(err)
	}

	signCmd := SignCmd()
	signCmd.SetArgs([]string{msgFile, "--private-key", keyBase + ".sig.key"})
	if err := signCmd.Execute(); err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	verifyCmd := VerifyCmd()
	verifyCmd.SetArgs([]string{msgFile, "--public-key", keyBase + ".sig.pub"})
	if err := verifyCmd.Execute(); err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
}
