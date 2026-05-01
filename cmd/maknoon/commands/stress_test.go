package commands

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
)

func TestIntegrationSecurityScenarios(t *testing.T) {
	SetJSONOutput(false)
	tmpDir := t.TempDir()

	t.Run("Verification Failure on Tampered File", func(t *testing.T) {
		keyBase := filepath.Join(tmpDir, "sig_fail_test")
		keygenCmd := KeygenCmd()
		keygenCmd.SetArgs([]string{"-o", keyBase, "--no-password"})
		if err := keygenCmd.Execute(); err != nil {
			t.Fatal(err)
		}

		msgFile := filepath.Join(tmpDir, "tampered.txt")
		if err := os.WriteFile(msgFile, []byte("Original message"), 0644); err != nil {
			t.Fatal(err)
		}

		signCmd := SignCmd()
		signCmd.SetArgs([]string{msgFile, "--private-key", keyBase + ".sig.key"})
		if err := signCmd.Execute(); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(msgFile, []byte("Tampered message"), 0644); err != nil {
			t.Fatal(err)
		}

		verifyCmd := VerifyCmd()
		verifyCmd.SetArgs([]string{msgFile, "--public-key", keyBase + ".sig.pub"})

		// In JSON mode (which might be active due to environment), we check stderr
		if JSONOutput {
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w
			_ = verifyCmd.Execute()
			_ = w.Close()
			os.Stderr = oldStderr
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			if !bytes.Contains(buf.Bytes(), []byte("FAILED")) {
				t.Error("Expected verification failure in JSON output")
			}
		} else {
			if err := verifyCmd.Execute(); err == nil {
				t.Error("Expected verification failure for tampered file")
			}
		}
	})

	t.Run("Vault Service Collision", func(t *testing.T) {
		vaultPath := "collision_test"
		pass := "pass"

		// Clean up previous test runs
		home := crypto.GetUserHomeDir()
		dbPath := filepath.Join(home, crypto.MaknoonDir, crypto.VaultsDir, vaultPath+".vault")
		_ = os.Remove(dbPath)
		defer os.Remove(dbPath)

		if err := os.Setenv("MAKNOON_PASSWORD", "secret1"); err != nil {
			t.Fatal(err)
		}
		setCmd := VaultCmd()
		setCmd.SetArgs([]string{"--vault", vaultPath, "--passphrase", pass, "set", "service1", "--json"})
		if err := setCmd.Execute(); err != nil {
			t.Fatal(err)
		}

		if err := os.Setenv("MAKNOON_PASSWORD", "secret2"); err != nil {
			t.Fatal(err)
		}
		setCmd.SetArgs([]string{"--vault", vaultPath, "--passphrase", pass, "set", "SERVICE1", "--json"})
		err := setCmd.Execute()
		if err == nil {
			t.Error("Expected collision error, got nil")
		}

		// Now set with overwrite
		setCmd.SetArgs([]string{"--vault", vaultPath, "--passphrase", pass, "set", "SERVICE1", "--json", "--overwrite"})
		if err := setCmd.Execute(); err != nil {
			t.Fatal(err)
		}

		os.Unsetenv("MAKNOON_PASSWORD")

		getCmd := VaultCmd()
		getCmd.SetArgs([]string{"--vault", vaultPath, "--passphrase", pass, "get", "service1", "--json"})

		SetJSONOutput(true)
		output := CaptureOutput(func() {
			_ = getCmd.Execute()
		})
		SetJSONOutput(false)

		if !strings.Contains(output, "secret2") {
			t.Errorf("Case-insensitive vault collision failed to overwrite. Output: %s", output)
		}
	})

	t.Run("Zip Slip Path Traversal Detection", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		header := &tar.Header{
			Name: "../evil.txt",
			Size: 4,
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("evil")); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}

		outDir := filepath.Join(tmpDir, "unsafe_extract")
		if err := os.MkdirAll(outDir, 0755); err != nil {
			t.Fatal(err)
		}

		err := crypto.ExtractArchive(bytes.NewReader(buf.Bytes()), outDir)
		if err == nil {
			t.Error("Expected error for Zip Slip attempt")
		}

		outsideFile := filepath.Join(filepath.Dir(outDir), "evil.txt")
		if _, err := os.Stat(outsideFile); err == nil {
			t.Errorf("Zip Slip SUCCEEDED! File written to %s", outsideFile)
			_ = os.Remove(outsideFile)
		}
	})
}

func TestIntegrationLargeFileConcurrency(t *testing.T) {
	SetJSONOutput(false)
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "large.bin")
	data := make([]byte, 10*1024*1024) // 10MB
	if err := os.WriteFile(inputFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	encryptedFile := inputFile + ".makn"
	passphrase := "large-file-pass"

	enc := EncryptCmd()
	enc.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", passphrase, "-j", "4", "--quiet"})
	if err := enc.Execute(); err != nil {
		t.Fatalf("Concurrent encryption failed: %v", err)
	}

	dec := DecryptCmd()
	restoredFile := filepath.Join(tmpDir, "large_restored.bin")
	dec.SetArgs([]string{encryptedFile, "-o", restoredFile, "-s", passphrase, "-j", "8", "--quiet"})
	if err := dec.Execute(); err != nil {
		t.Fatalf("Concurrent decryption failed: %v", err)
	}

	restored, err := os.ReadFile(restoredFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, restored) {
		t.Error("Large file restored content mismatch")
	}
}

func TestIntegrationStealthMode(t *testing.T) {
	SetJSONOutput(false)
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "secret.txt")
	content := []byte("Stealth Mode Integration Test")
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	encryptedFile := filepath.Join(tmpDir, "secret.makn")
	passphrase := "stealth-pass"

	// 1. Encrypt with --stealth
	enc := EncryptCmd()
	enc.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", passphrase, "--stealth", "--quiet"})
	if err := enc.Execute(); err != nil {
		t.Fatalf("Stealth encryption failed: %v", err)
	}

	// Verify magic bytes are NOT present
	raw, err := os.ReadFile(encryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 4 && (string(raw[:4]) == crypto.MagicHeader || string(raw[:4]) == crypto.MagicHeaderAsym) {
		t.Errorf("Security failure: Magic bytes found in stealth file")
	}

	// 2. Decrypt with --stealth
	dec := DecryptCmd()
	restoredFile := filepath.Join(tmpDir, "secret.restored")
	dec.SetArgs([]string{encryptedFile, "-o", restoredFile, "-s", passphrase, "--stealth", "--quiet"})
	if err := dec.Execute(); err != nil {
		t.Fatalf("Stealth decryption failed: %v", err)
	}

	restored, err := os.ReadFile(restoredFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, restored) {
		t.Error("Stealth restored content mismatch")
	}

	// 3. Info with --stealth
	info := InfoCmd()
	info.SetArgs([]string{encryptedFile, "--stealth", "--json"})
	output := CaptureOutput(func() {
		// Manually sync since main.go isn't running
		SetJSONOutput(true)
		defer func() { SetJSONOutput(false) }()
		_ = info.Execute()
	})
	if !strings.Contains(output, "\"is_stealth\"") || !strings.Contains(output, "true") {
		t.Errorf("Info failed to detect stealth mode. Output: %s", output)
	}
}
