package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/a-khallaf/maknoon/cmd/maknoon/commands"
	"github.com/a-khallaf/maknoon/pkg/crypto"
)

func TestIntegrationSymmetricPassphraseFlag(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("Hello, Maknoon!")
	os.WriteFile(inputFile, content, 0644)

	encryptedFile := inputFile + ".makn"
	decryptedFile := filepath.Join(tmpDir, "restored.txt")
	passphrase := "test-passphrase-123"

	// 1. Encrypt with -s flag
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", passphrase, "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 2. Decrypt with -s flag
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "-s", passphrase, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// 3. Verify
	restored, _ := os.ReadFile(decryptedFile)
	if !bytes.Equal(content, restored) {
		t.Fatalf("Restored content mismatch")
	}
}

func TestIntegrationDirectoryArchive(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "source")
	os.MkdirAll(srcDir, 0755)
	os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("data1"), 0644)
	os.WriteFile(filepath.Join(srcDir, "file2.txt"), []byte("data2"), 0644)

	encryptedFile := filepath.Join(tmpDir, "archive.makn")
	restoredDir := filepath.Join(tmpDir, "restored_dir")
	passphrase := "dir-pass"

	// 1. Encrypt directory (should trigger archive mode)
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{srcDir, "-o", encryptedFile, "-s", passphrase, "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Directory encryption failed: %v", err)
	}

	// 2. Decrypt directory
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", restoredDir, "-s", passphrase, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Directory decryption failed: %v", err)
	}

	// 3. Verify
	f1, _ := os.ReadFile(filepath.Join(restoredDir, "source", "file1.txt"))
	if string(f1) != "data1" {
		t.Errorf("File1 mismatch: %s", string(f1))
	}
}

func TestIntegrationAsymmetricEncryptedKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyBase := filepath.Join(tmpDir, "id_test")
	passphrase := "key-pass"

	// 1. Keygen with passphrase
	genCmd := commands.KeygenCmd()
	genCmd.SetArgs([]string{"-o", keyBase, "-s", passphrase})
	if err := genCmd.Execute(); err != nil {
		t.Fatalf("Keygen failed: %v", err)
	}

	// 2. Encrypt with public key
	inputFile := filepath.Join(tmpDir, "data.txt")
	content := []byte("Sensitive data")
	os.WriteFile(inputFile, content, 0644)

	encryptedFile := inputFile + ".makn"
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "--public-key", keyBase + ".kem.pub", "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Asymmetric encryption failed: %v", err)
	}

	// 3. Decrypt with private key (prompts for passphrase)
	decryptedFile := filepath.Join(tmpDir, "restored.txt")
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "--private-key", keyBase + ".kem.key", "-s", passphrase, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Asymmetric decryption failed: %v", err)
	}

	// 4. Verify
	restored, _ := os.ReadFile(decryptedFile)
	if !bytes.Equal(content, restored) {
		t.Fatalf("Restored content mismatch")
	}
}

func TestIntegrationCompression(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "compressible.txt")
	// Highly compressible data
	content := bytes.Repeat([]byte("A"), 20000)
	os.WriteFile(inputFile, content, 0644)

	encryptedFile := inputFile + ".makn"
	decryptedFile := filepath.Join(tmpDir, "restored.txt")
	passphrase := "comp-pass"

	// 1. Encrypt with compression
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", passphrase, "--compress", "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Compressed encryption failed: %v", err)
	}

	// Check that it's actually smaller (including headers overhead)
	stat, _ := os.Stat(encryptedFile)
	if stat.Size() > 1000 {
		t.Errorf("Compression didn't seem to work, size: %d", stat.Size())
	}

	// 2. Decrypt
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "-s", passphrase, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Compressed decryption failed: %v", err)
	}

	// 3. Verify
	restored, _ := os.ReadFile(decryptedFile)
	if !bytes.Equal(content, restored) {
		t.Fatalf("Compressed restored content mismatch")
	}
}

func TestIntegrationSignVerify(t *testing.T) {
	tmpDir := t.TempDir()
	keyBase := filepath.Join(tmpDir, "id_test_sig")

	// Keygen
	genCmd := commands.KeygenCmd()
	genCmd.SetArgs([]string{"-o", keyBase, "--no-password"})
	genCmd.Execute()

	inputFile := filepath.Join(tmpDir, "message.txt")
	os.WriteFile(inputFile, []byte("PQ Authentication"), 0644)

	signCmd := commands.SignCmd()
	signCmd.SetArgs([]string{inputFile, "--private-key", keyBase + ".sig.key"})
	if err := signCmd.Execute(); err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	verifyCmd := commands.VerifyCmd()
	verifyCmd.SetArgs([]string{inputFile, "--public-key", keyBase + ".sig.pub"})
	if err := verifyCmd.Execute(); err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
}

func TestIntegrationKeygenCustomProfile(t *testing.T) {
	tmpDir := t.TempDir()
	
	// 1. Create a Custom Profile for Key Protection
	profileFile := filepath.Join(tmpDir, "key_prof.json")
	// ID 110, AES-GCM, high iterations
	profileJSON := `{
		"id": 110,
		"cipher": 1,
		"kdf": 0,
		"kdf_iterations": 2,
		"kdf_memory": 32768,
		"kdf_threads": 2,
		"salt_size": 32,
		"nonce_size": 12
	}`
	os.WriteFile(profileFile, []byte(profileJSON), 0644)

	keyBase := filepath.Join(tmpDir, "id_custom_prof")
	passphrase := "key-protect-pass"

	// 2. Generate Identity protected by this profile
	genCmd := commands.KeygenCmd()
	genCmd.SetArgs([]string{"-o", keyBase, "-s", passphrase, "--profile-file", profileFile})
	if err := genCmd.Execute(); err != nil {
		t.Fatalf("Keygen with custom profile failed: %v", err)
	}

	// 3. Use the protected key to encrypt a file
	inputFile := filepath.Join(tmpDir, "data.txt")
	os.WriteFile(inputFile, []byte("Encrypted with custom-profile-protected key"), 0644)
	
	encryptedFile := inputFile + ".makn"
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "--public-key", keyBase + ".kem.pub", "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Encryption with custom-profile key failed: %v", err)
	}

	// 4. Decrypt using the private key (Must auto-detect key protection profile)
	// IMPORTANT: To decrypt the PRIVATE KEY, we need the profile file!
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", "-", "--private-key", keyBase + ".kem.key", "-s", passphrase, "--profile-file", profileFile, "--quiet"})
	
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	
	if err := decCmd.Execute(); err != nil {
		w.Close()
		os.Stdout = oldStdout
		t.Fatalf("Decryption with custom-profile key failed: %v", err)
	}
	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	if !strings.Contains(buf.String(), "Encrypted with custom-profile-protected key") {
		t.Errorf("Decrypted content mismatch or key unlocking failed")
	}
}

func TestIntegrationRandomProfileStress(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "stress_input.txt")
	content := []byte("Stress testing randomized profiles")
	os.WriteFile(inputFile, content, 0644)
	passphrase := "stress-pass"

	for i := 0; i < 5; i++ {
		// 1. Generate a random profile via CLI
		profileFile := filepath.Join(tmpDir, fmt.Sprintf("random_%d.json", i))
		profCmd := commands.ProfilesCmd()
		
		// Capture stdout to save the JSON
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		
		profCmd.SetArgs([]string{"--generate"})
		if err := profCmd.Execute(); err != nil {
			w.Close()
			os.Stdout = oldStdout
			t.Fatalf("Failed to generate random profile: %v", err)
		}
		
		w.Close()
		os.Stdout = oldStdout
		
		var jsonBuf bytes.Buffer
		io.Copy(&jsonBuf, r)
		os.WriteFile(profileFile, jsonBuf.Bytes(), 0644)

		// 2. Encrypt using this random profile
		encryptedFile := filepath.Join(tmpDir, fmt.Sprintf("stress_%d.makn", i))
		encCmd := commands.EncryptCmd()
		encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", passphrase, "--profile-file", profileFile, "--quiet"})
		if err := encCmd.Execute(); err != nil {
			t.Fatalf("Encryption failed with random profile %d: %v", i, err)
		}

		// 3. Decrypt (Auto-detect)
		decryptedFile := filepath.Join(tmpDir, fmt.Sprintf("stress_restored_%d.txt", i))
		decCmd := commands.DecryptCmd()
		var dp crypto.DynamicProfile
		json.Unmarshal(jsonBuf.Bytes(), &dp)
		
		args := []string{encryptedFile, "-o", decryptedFile, "-s", passphrase, "--quiet"}
		if dp.ID() < 128 {
			args = append(args, "--profile-file", profileFile)
		}
		
		decCmd.SetArgs(args)
		if err := decCmd.Execute(); err != nil {
			t.Fatalf("Decryption failed with random profile %d (ID: %d): %v", i, dp.ID(), err)
		}

		// 4. Verify
		restored, _ := os.ReadFile(decryptedFile)
		if !bytes.Equal(content, restored) {
			t.Fatalf("Content mismatch with random profile %d (ID: %d)", i, dp.ID())
		}
	}
}

func TestIntegrationGCMSIVProfile(t *testing.T) {
	tmpDir := t.TempDir()

	profileFile := filepath.Join(tmpDir, "siv_profile.json")
	// Profile ID 150 (Portable), AES-GCM-SIV (2), 1 iteration Argon2
	profileJSON := `{
		"id": 150,
		"cipher": 2,
		"kdf": 0,
		"kdf_iterations": 1,
		"kdf_memory": 16384,
		"kdf_threads": 4,
		"salt_size": 16,
		"nonce_size": 12
	}`
	os.WriteFile(profileFile, []byte(profileJSON), 0644)

	inputFile := filepath.Join(tmpDir, "siv_test.txt")
	content := []byte("AES-GCM-SIV Nonce-Misuse Resistance Test")
	os.WriteFile(inputFile, content, 0644)

	encryptedFile := inputFile + ".makn"
	passphrase := "siv-pass"

	// 1. Encrypt
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", passphrase, "--profile-file", profileFile, "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("SIV profile encryption failed: %v", err)
	}

	// 2. Decrypt (Auto-detect from header)
	decryptedFile := filepath.Join(tmpDir, "siv_restored.txt")
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "-s", passphrase, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("SIV profile decryption failed: %v", err)
	}

	// 3. Verify
	restored, _ := os.ReadFile(decryptedFile)
	if !bytes.Equal(content, restored) {
		t.Fatalf("SIV restored content mismatch")
	}
}

func TestIntegrationSelfContainedProfile(t *testing.T) {
	tmpDir := t.TempDir()
	
	// 1. Create a "Portable" Profile JSON (ID >= 128)
	profileFile := filepath.Join(tmpDir, "portable_profile.json")
	// Profile ID 200, AES-GCM, 1 iteration Argon2
	profileJSON := `{
		"id": 200,
		"cipher": 1,
		"kdf": 0,
		"kdf_iterations": 1,
		"kdf_memory": 16384,
		"kdf_threads": 4,
		"salt_size": 16,
		"nonce_size": 12
	}`
	os.WriteFile(profileFile, []byte(profileJSON), 0644)

	inputFile := filepath.Join(tmpDir, "portable_test.txt")
	content := []byte("Portable Profile Content (Packed in Header)")
	os.WriteFile(inputFile, content, 0644)
	
	encryptedFile := inputFile + ".makn"
	passphrase := "portable-pass"

	// 2. Encrypt using the profile file
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", passphrase, "--profile-file", profileFile, "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Portable profile encryption failed: %v", err)
	}

	// 3. Decrypt WITHOUT the profile file (Self-Contained Portability)
	decryptedFile := filepath.Join(tmpDir, "portable_restored.txt")
	decCmd := commands.DecryptCmd()
	// NOTE: We do NOT pass --profile-file here!
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "-s", passphrase, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Portable profile decryption failed: %v", err)
	}

	// 4. Verify
	restored, _ := os.ReadFile(decryptedFile)
	if !bytes.Equal(content, restored) {
		t.Fatalf("Portable profile restored content mismatch")
	}
}

func TestIntegrationSecretProfile(t *testing.T) {
	tmpDir := t.TempDir()
	
	// 1. Create a "Secret" Profile JSON
	profileFile := filepath.Join(tmpDir, "secret_profile.json")
	// Profile ID 100, AES-GCM, 1 iteration Argon2
	profileJSON := `{
		"id": 100,
		"cipher": 1,
		"kdf": 0,
		"kdf_iterations": 1,
		"kdf_memory": 16384,
		"kdf_threads": 4,
		"salt_size": 16,
		"nonce_size": 12
	}`
	os.WriteFile(profileFile, []byte(profileJSON), 0644)

	inputFile := filepath.Join(tmpDir, "secret_test.txt")
	content := []byte("Secret Profile Content")
	os.WriteFile(inputFile, content, 0644)
	
	encryptedFile := inputFile + ".makn"
	passphrase := "secret-profile-pass"

	// 2. Encrypt using the profile file
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", passphrase, "--profile-file", profileFile, "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Secret profile encryption failed: %v", err)
	}

	// 3. Decrypt using the SAME profile file (Secret Portability)
	decryptedFile := filepath.Join(tmpDir, "secret_restored.txt")
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "-s", passphrase, "--profile-file", profileFile, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Secret profile decryption failed: %v", err)
	}

	// 4. Verify
	restored, _ := os.ReadFile(decryptedFile)
	if !bytes.Equal(content, restored) {
		t.Fatalf("Secret profile restored content mismatch")
	}
}

func TestIntegrationProfileV2(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "v2_test.txt")
	content := []byte("AES-GCM Profile Agility Test Content")
	os.WriteFile(inputFile, content, 0644)
	
	encryptedFile := inputFile + ".makn"
	decryptedFile := filepath.Join(tmpDir, "v2_restored.txt")
	passphrase := "profile-v2-secret"

	// 1. Encrypt with Profile 2 (AES-GCM)
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", passphrase, "--profile", "2", "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Profile 2 encryption failed: %v", err)
	}

	// 2. Decrypt (Should auto-detect Profile 2)
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "-s", passphrase, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Profile 2 decryption failed: %v", err)
	}

	// 3. Verify
	restored, _ := os.ReadFile(decryptedFile)
	if !bytes.Equal(content, restored) {
		t.Fatalf("Profile 2 restored content mismatch")
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
