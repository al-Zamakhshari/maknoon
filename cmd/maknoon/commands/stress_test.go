package commands

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/a-khallaf/maknoon/pkg/crypto"
)

func TestIntegrationSecurityScenarios(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Verification Failure on Tampered File", func(t *testing.T) {
		keyBase := filepath.Join(tmpDir, "sig_fail_test")
		keygenCmd := KeygenCmd()
		keygenCmd.SetArgs([]string{"-o", keyBase, "--no-password"})
		keygenCmd.Execute()

		msgFile := filepath.Join(tmpDir, "tampered.txt")
		os.WriteFile(msgFile, []byte("Original message"), 0644)

		signCmd := SignCmd()
		signCmd.SetArgs([]string{msgFile, "--private-key", keyBase + ".sig.key"})
		signCmd.Execute()

		// Tamper with the file
		os.WriteFile(msgFile, []byte("Tampered message"), 0644)

		verifyCmd := VerifyCmd()
		verifyCmd.SetArgs([]string{msgFile, "--public-key", keyBase + ".sig.pub"})
		if err := verifyCmd.Execute(); err == nil {
			t.Error("Expected verification failure for tampered file, but it passed")
		}
	})

	t.Run("Vault Service Collision", func(t *testing.T) {
		vPath := filepath.Join(tmpDir, "collision.db")
		pass := "pass"

		setCmd := VaultCmd()
		// Set first secret
		setCmd.SetArgs([]string{"--vault", vPath, "--passphrase", pass, "set", "service1", "secret1"})
		setCmd.Execute()

		// Overwrite with second secret
		setCmd.SetArgs([]string{"--vault", vPath, "--passphrase", pass, "set", "service1", "secret2"})
		setCmd.Execute()

		getCmd := VaultCmd()
		getCmd.SetArgs([]string{"--vault", vPath, "--passphrase", pass, "get", "service1"})
		output := captureOutput(func() {
			getCmd.Execute()
		})

		if !strings.Contains(output, "secret2") {
			t.Errorf("Vault collision handling failed. Expected secret2, got: %s", output)
		}
	})

	t.Run("Zip Slip Path Traversal Detection", func(t *testing.T) {
		// Create a malicious archive in memory
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)

		// Malicious entry attempting to escape output directory
		header := &tar.Header{
			Name: "../outside.txt",
			Mode: 0600,
			Size: 4,
		}
		tw.WriteHeader(header)
		tw.Write([]byte("evil"))
		tw.Close()

		outDir := filepath.Join(tmpDir, "extract_safety")
		os.MkdirAll(outDir, 0755)

		// Call ExtractArchive directly (internal logic verification)
		err := crypto.ExtractArchive(&buf, outDir)
		if err == nil {
			t.Fatal("Expected error for Zip Slip archive, but got nil")
		}
		if !strings.Contains(err.Error(), "illegal file path") {
			t.Errorf("Expected 'illegal file path' error, got: %v", err)
		}

		// Verify file was NOT created outside
		outsideFile := filepath.Join(tmpDir, "outside.txt")
		if _, err := os.Stat(outsideFile); err == nil {
			t.Error("VULNERABILITY CONFIRMED: File was created outside the target directory!")
			os.Remove(outsideFile)
		}
	})
}

func TestIntegrationLargeFileConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file concurrency test in short mode")
	}

	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "large.bin")
	encFile := inputFile + ".makn"
	decFile := inputFile + ".dec"

	// Create a 10MB file (enough to have many 64KB chunks)
	data := make([]byte, 10*1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	os.WriteFile(inputFile, data, 0644)
	pass := "large-pass"

	// Encrypt with high concurrency
	encCmd := EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encFile, "-s", pass, "-j", "8"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Large file encryption failed: %v", err)
	}

	// Decrypt with different concurrency
	decCmd := DecryptCmd()
	decCmd.SetArgs([]string{encFile, "-o", decFile, "-s", pass, "-j", "1"}) // Sequential decryption of parallel encryption
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Large file decryption failed: %v", err)
	}

	res, _ := os.ReadFile(decFile)
	if len(res) != len(data) {
		t.Fatalf("Restored size mismatch: got %d, want %d", len(res), len(data))
	}
	// Check first and last bytes to save time
	if res[0] != data[0] || res[len(res)-1] != data[len(data)-1] {
		t.Fatal("Data corruption in large file round-trip")
	}
}
