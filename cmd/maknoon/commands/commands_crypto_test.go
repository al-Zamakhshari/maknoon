package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestDecryptFailures(t *testing.T) {
	SetJSONOutput(false)
	tmpDir := t.TempDir()

	t.Run("File not found", func(t *testing.T) {
		dec := DecryptCmd()
		dec.SetArgs([]string{filepath.Join(tmpDir, "non-existent.makn")})

		output := CaptureOutput(func() {
			_ = dec.Execute()
		})

		if !strings.Contains(output, "no such file or directory") {
			t.Errorf("Expected error for non-existent file, got: %s", output)
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
		dec.SetArgs([]string{inputFile + ".makn", "-s", "wrong-pass", "-o", inputFile, "--quiet"})

		output := CaptureOutput(func() {
			_ = dec.Execute()
		})

		if !strings.Contains(output, "authentication failed") && !strings.Contains(output, "output path already exists") {
			t.Errorf("Expected decryption failure for wrong passphrase, got: %s", output)
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
