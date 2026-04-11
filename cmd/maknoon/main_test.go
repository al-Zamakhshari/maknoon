package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/a-khallaf/maknoon/cmd/maknoon/commands"
)

func TestIntegrationSymmetricPassphraseFlag(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "test.txt")
	encryptedFile := inputFile + ".makn"
	decryptedFile := filepath.Join(tmpDir, "restored.txt")
	content := []byte("Integration testing with flags!")
	passphrase := "automation-secret"

	os.WriteFile(inputFile, content, 0644)

	// 1. Encrypt
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "--passphrase", passphrase})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Encryption command failed: %v", err)
	}

	// 2. Decrypt
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "--passphrase", passphrase})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Decryption command failed: %v", err)
	}

	// 3. Verify
	restored, _ := os.ReadFile(decryptedFile)
	if !bytes.Equal(content, restored) {
		t.Fatalf("Restored content mismatch. Got: %s", string(restored))
	}
}

func TestIntegrationDirectoryArchive(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "source")
	os.Mkdir(srcDir, 0755)

	file1 := filepath.Join(srcDir, "a.txt")
	file2 := filepath.Join(srcDir, "sub/b.txt")
	os.MkdirAll(filepath.Dir(file2), 0755)

	os.WriteFile(file1, []byte("file a"), 0644)
	os.WriteFile(file2, []byte("file b"), 0644)

	encryptedFile := filepath.Join(tmpDir, "archive.makn")
	destDir := filepath.Join(tmpDir, "restored_here") // Do NOT pre-create this directory
	passphrase := "dir-secret"

	// 1. Encrypt Directory
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{srcDir, "-o", encryptedFile, "--passphrase", passphrase})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Directory encryption failed: %v", err)
	}

	// 2. Decrypt Archive
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", destDir, "--passphrase", passphrase})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Directory decryption failed: %v", err)
	}

	// DEBUG: List all files extracted
	t.Log("Listing all files in destDir:")
	filepath.Walk(destDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(destDir, path)
		t.Logf("  - %s (Dir: %v, Mode: %v)", rel, info.IsDir(), info.Mode())
		return nil
	})

	// 3. Verify Files
	targetA := filepath.Join(destDir, "source", "a.txt")
	checkA, err := os.ReadFile(targetA)
	if err != nil {
		t.Fatalf("Failed to read restored file A: %v", err)
	}
	if string(checkA) != "file a" {
		t.Errorf("File A content mismatch: %s", string(checkA))
	}

	targetB := filepath.Join(destDir, "source", "sub", "b.txt")
	checkB, err := os.ReadFile(targetB)
	if err != nil {
		t.Fatalf("Failed to read restored file B: %v", err)
	}
	if string(checkB) != "file b" {
		t.Errorf("File B content mismatch: %s", string(checkB))
	}
}

func TestIntegrationAsymmetricEncryptedKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyBase := filepath.Join(tmpDir, "id_test")
	passphrase := "key-lock-123"

	// 1. Keygen with password
	genCmd := commands.KeygenCmd()
	genCmd.SetArgs([]string{"-o", keyBase, "--passphrase", passphrase})
	os.Setenv("MAKNOON_PASSPHRASE", passphrase)
	defer os.Unsetenv("MAKNOON_PASSPHRASE")

	if err := genCmd.Execute(); err != nil {
		t.Fatalf("Keygen integration failed: %v", err)
	}

	// 2. Encrypt File using Public Key
	inputFile := filepath.Join(tmpDir, "data.txt")
	os.WriteFile(inputFile, []byte("PQ Security"), 0644)
	encFile := inputFile + ".makn"

	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encFile, "--public-key", keyBase + ".kem.pub"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Asymmetric encryption failed: %v", err)
	}

	// 3. Decrypt using Protected Private Key (automatically uses MAKNOON_PASSPHRASE)
	restoredFile := filepath.Join(tmpDir, "data.restored.txt")
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encFile, "-o", restoredFile, "--private-key", keyBase + ".kem.key"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Asymmetric decryption failed: %v", err)
	}

	res, _ := os.ReadFile(restoredFile)
	if string(res) != "PQ Security" {
		t.Errorf("Asymmetric restored mismatch: %s", string(res))
	}
}

func TestIntegrationCompression(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "compressible.txt")
	encryptedFile := inputFile + ".makn"
	decryptedFile := filepath.Join(tmpDir, "restored.txt")

	// Create highly redundant data (very compressible)
	content := bytes.Repeat([]byte("COMPRESS-ME-PLEASE-"), 1000)
	os.WriteFile(inputFile, content, 0644)
	passphrase := "compress-secret"

	// 1. Encrypt with Compression
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "--passphrase", passphrase, "--compress"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Compression encryption failed: %v", err)
	}

	// 2. Decrypt (Auto-detects compression)
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "--passphrase", passphrase})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Compression decryption failed: %v", err)
	}

	// 3. Verify
	restored, _ := os.ReadFile(decryptedFile)
	if !bytes.Equal(content, restored) {
		t.Fatal("Restored content mismatch after compression")
	}

	// 4. Sanity check
	statOrig, _ := os.Stat(inputFile)
	statEnc, _ := os.Stat(encryptedFile)
	if statEnc.Size() >= statOrig.Size() {
		t.Logf("Warning: Encrypted size (%d) not smaller than original (%d).", statEnc.Size(), statOrig.Size())
	} else {
		t.Logf("Compression success: %d -> %d bytes", statOrig.Size(), statEnc.Size())
	}
}

func TestIntegrationVaultAutomation(t *testing.T) {
	vName := filepath.Join(t.TempDir(), "vault.db")
	passphrase := "vault-master-123"
	service := "test-service"
	password := "ultra-secret-123"
	user := "test-user"

	// 1. Set
	setCmd := commands.VaultCmd()
	setCmd.SetArgs([]string{"--vault", vName, "--passphrase", passphrase, "set", service, password, "--user", user})
	if err := setCmd.Execute(); err != nil {
		t.Fatalf("Vault set failed: %v", err)
	}

	// 2. Get
	getCmd := commands.VaultCmd()
	getCmd.SetArgs([]string{"--vault", vName, "--passphrase", passphrase, "get", service})

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	getCmd.Execute()
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()
	if !strings.Contains(output, password) {
		t.Errorf("Vault get mismatch: %s", output)
	}
}

func TestIntegrationSignVerify(t *testing.T) {
	tmpDir := t.TempDir()
	keyBase := filepath.Join(tmpDir, "id_test_sig")
	genCmd := commands.KeygenCmd()
	genCmd.SetArgs([]string{"-o", keyBase, "--no-password"})
	genCmd.Execute()

	inputFile := filepath.Join(tmpDir, "message.txt")
	os.WriteFile(inputFile, []byte("PQ Authentication"), 0644)

	signCmd := commands.SignCmd()
	signCmd.SetArgs([]string{inputFile, "--private-key", keyBase + ".sig.key"})
	signCmd.Execute()

	verifyCmd := commands.VerifyCmd()
	verifyCmd.SetArgs([]string{inputFile, "--public-key", keyBase + ".sig.pub"})
	if err := verifyCmd.Execute(); err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
}

func TestIntegrationPipesAndEnv(t *testing.T) {
	tmpDir := t.TempDir()
	content := "Pipe integration test data"
	passphrase := "pipe-secret-123"

	// 1. Test Encrypt from Stdin to File
	encCmd := commands.EncryptCmd()
	encFile := filepath.Join(tmpDir, "pipe.makn")
	encCmd.SetArgs([]string{"-", "-o", encFile, "-s", passphrase, "--quiet"})

	// Mock stdin
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	w.Write([]byte(content))
	w.Close()

	if err := encCmd.Execute(); err != nil {
		os.Stdin = oldStdin
		t.Fatalf("Pipe encryption failed: %v", err)
	}
	os.Stdin = oldStdin

	// 2. Test Decrypt from File to Stdout
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encFile, "-o", "-", "-s", passphrase, "--quiet"})

	// Mock stdout
	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut

	if err := decCmd.Execute(); err != nil {
		wOut.Close()
		os.Stdout = oldStdout
		t.Fatalf("Pipe decryption failed: %v", err)
	}
	wOut.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, rOut)
	if buf.String() != content {
		t.Errorf("Pipe output mismatch. Got: %s, Want: %s", buf.String(), content)
	}
}

func TestIntegrationFullFeatureStress(t *testing.T) {
	tmpDir := t.TempDir()

	srcDir := filepath.Join(tmpDir, "complex_source")
	os.MkdirAll(filepath.Join(srcDir, "sub"), 0755)
	os.WriteFile(filepath.Join(srcDir, "data.bin"), bytes.Repeat([]byte{0x42}, 100000), 0644)

	keyBase := filepath.Join(tmpDir, "id_complex")
	genCmd := commands.KeygenCmd()
	genCmd.SetArgs([]string{"-o", keyBase, "--no-password"})
	genCmd.Execute()

	encryptedFile := filepath.Join(tmpDir, "complex.makn")
	restoredDir := filepath.Join(tmpDir, "complex_restored")

	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{srcDir, "-o", encryptedFile, "--public-key", keyBase + ".kem.pub", "--compress"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Full-feature encryption failed: %v", err)
	}

	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", restoredDir, "--private-key", keyBase + ".kem.key"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Full-feature decryption failed: %v", err)
	}

	orig, _ := os.ReadFile(filepath.Join(srcDir, "data.bin"))
	restored, err := os.ReadFile(filepath.Join(restoredDir, "complex_source", "data.bin"))
	if err != nil {
		t.Fatalf("Restored file not found: %v", err)
	}
	if !bytes.Equal(orig, restored) {
		t.Fatal("Full-feature round-trip resulted in data corruption")
	}
}
