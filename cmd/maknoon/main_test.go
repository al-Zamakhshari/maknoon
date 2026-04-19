package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/al-Zamakhshari/maknoon/cmd/maknoon/commands"
	"github.com/spf13/cobra"
)

// runRootCmd helper to run the full CLI with global flags and capture combined output
func runRootCmd(args ...string) string {
	commands.JSONOutput = false
	rootCmd := &cobra.Command{
		Use: "maknoon",
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			if commands.JSONOutput || os.Getenv("MAKNOON_JSON") == "1" {
				commands.JSONOutput = true
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
			}
		},
	}
	rootCmd.PersistentFlags().BoolVar(&commands.JSONOutput, "json", false, "Output results in JSON format")

	rootCmd.AddCommand(commands.EncryptCmd())
	rootCmd.AddCommand(commands.DecryptCmd())
	rootCmd.AddCommand(commands.InfoCmd())
	rootCmd.AddCommand(commands.IdentityCmd())
	rootCmd.AddCommand(commands.KeygenCmd())
	rootCmd.AddCommand(commands.ProfilesCmd())
	rootCmd.AddCommand(commands.GenCmd())
	rootCmd.AddCommand(commands.VaultCmd())
	rootCmd.AddCommand(commands.SignCmd())
	rootCmd.AddCommand(commands.VerifyCmd())

	rootCmd.SetArgs(args)

	var buf bytes.Buffer
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	oldJSONWriter := commands.JSONWriter
	oldGlobalWriter := commands.GlobalContext.JSONWriter

	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w
	commands.JSONWriter = w
	commands.GlobalContext.JSONWriter = w

	_ = rootCmd.Execute()

	w.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	commands.JSONWriter = oldJSONWriter
	commands.GlobalContext.JSONWriter = oldGlobalWriter
	io.Copy(&buf, r)
	return buf.String()
}

func TestIntegrationBasicSymmetric(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.txt")
	content := []byte("Hello, Maknoon!")
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	encryptedFile := inputFile + ".makn"
	decryptedFile := filepath.Join(tmpDir, "restored.txt")
	passphrase := "test-secret-pass"

	// 1. Encrypt
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", passphrase, "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 2. Decrypt
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "-s", passphrase, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// 3. Verify
	restored, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, restored) {
		t.Errorf("Content mismatch. Got %s, want %s", restored, content)
	}
}

func TestIntegrationDirectoryEncryption(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "source")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("data1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "file2.txt"), []byte("data2"), 0644); err != nil {
		t.Fatal(err)
	}

	encryptedFile := filepath.Join(tmpDir, "archive.makn")
	restoredDir := filepath.Join(tmpDir, "restored")
	passphrase := "dir-pass"

	// 1. Encrypt Directory
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{srcDir, "-o", encryptedFile, "-s", passphrase, "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Directory encryption failed: %v", err)
	}

	// 2. Decrypt to new Directory
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", restoredDir, "-s", passphrase, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Directory decryption failed: %v", err)
	}

	// 3. Verify files (they are restored inside 'source' subdir of restoredDir)
	d1, err := os.ReadFile(filepath.Join(restoredDir, "source", "file1.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(d1) != "data1" {
		t.Error("file1 content mismatch")
	}
}

func TestIntegrationProfiles(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "profile_test.txt")
	content := []byte("Testing with Profile 2 (AES-GCM)")
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	encryptedFile := inputFile + ".makn"
	decryptedFile := filepath.Join(tmpDir, "profile_restored.txt")
	passphrase := "profile-pass"

	// 1. Encrypt with Profile 2
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", passphrase, "--profile", "2", "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Profile 2 encryption failed: %v", err)
	}

	// 2. Decrypt (Auto-detect from header)
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "-s", passphrase, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Profile 2 decryption failed: %v", err)
	}

	// 3. Verify
	restored, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, restored) {
		t.Errorf("Profile 2 content mismatch")
	}
}

func TestIntegrationCompression(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "compress_test.txt")
	content := bytes.Repeat([]byte("High entropy? No, highly compressible! "), 100)
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	encryptedFile := inputFile + ".makn"
	decryptedFile := filepath.Join(tmpDir, "compress_restored.txt")
	passphrase := "compress-pass"

	// 1. Encrypt with Compression
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", passphrase, "--compress", "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Compressed encryption failed: %v", err)
	}

	// 2. Decrypt (Auto-detect compression from header)
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "-s", passphrase, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Compressed decryption failed: %v", err)
	}

	// 3. Verify
	restored, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, restored) {
		t.Errorf("Compressed content mismatch")
	}
}

func TestIntegrationAsymmetricPQ(t *testing.T) {
	tmpDir := t.TempDir()
	keyBase := filepath.Join(tmpDir, "id_test")

	// 1. Keygen
	genCmd := commands.KeygenCmd()
	genCmd.SetArgs([]string{"-o", keyBase, "--no-password"})
	if err := genCmd.Execute(); err != nil {
		t.Fatalf("Keygen failed: %v", err)
	}

	inputFile := filepath.Join(tmpDir, "pq_test.txt")
	if err := os.WriteFile(inputFile, []byte("PQ Authentication"), 0644); err != nil {
		t.Fatal(err)
	}
	encryptedFile := inputFile + ".makn"
	restoredFile := filepath.Join(tmpDir, "pq_restored.txt")

	// 2. Encrypt with Public Key
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "--public-key", keyBase + ".kem.pub", "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("PQ encryption failed: %v", err)
	}

	// 3. Decrypt with Private Key
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", restoredFile, "--private-key", keyBase + ".kem.key", "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("PQ decryption failed: %v", err)
	}

	// 4. Verify
	restored, err := os.ReadFile(restoredFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != "PQ Authentication" {
		t.Errorf("PQ restored content mismatch")
	}
}

func TestIntegrationSecretProfileAutoDiscovery(t *testing.T) {
	// Setup custom home dir for profile discovery
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	if err := os.Setenv("HOME", tmpDir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Setenv("HOME", oldHome); err != nil {
			t.Errorf("Failed to restore HOME: %v", err)
		}
	}()

	profDir := filepath.Join(tmpDir, ".maknoon", "profiles")
	if err := os.MkdirAll(profDir, 0700); err != nil {
		t.Fatal(err)
	}

	// 1. Create a "Secret" Profile JSON (ID 50)
	profileFile := filepath.Join(profDir, "50.json")
	// Profile ID 50, AES-GCM, 1 iteration Argon2
	profileJSON := `{
		"id": 50,
		"cipher": 1,
		"kdf": 0,
		"kdf_iterations": 1,
		"kdf_memory": 16384,
		"kdf_threads": 4,
		"salt_size": 16,
		"nonce_size": 12
	}`
	if err := os.WriteFile(profileFile, []byte(profileJSON), 0644); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(profileFile) }()

	inputFile := filepath.Join(tmpDir, "secret_discovery_test.txt")
	content := []byte("Discovery Test Content")
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	encryptedFile := inputFile + ".makn"
	passphrase := "discovery-pass"

	// 2. Encrypt using the profile ID (should trigger discovery)
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", passphrase, "--profile", "50", "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Secret discovery encryption failed: %v", err)
	}

	// 3. Decrypt WITHOUT explicit profile (should trigger discovery from header ID)
	decryptedFile := filepath.Join(tmpDir, "discovery_restored.txt")
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "-s", passphrase, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Secret discovery decryption failed: %v", err)
	}

	// 4. Verify
	restored, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, restored) {
		t.Fatalf("Discovery restored content mismatch")
	}
}

func TestIntegrationKeygenCustomProfile(t *testing.T) {
	tmpDir := t.TempDir()
	profileFile := filepath.Join(tmpDir, "custom_profile.json")
	// Profile ID 140 (Portable), AES-GCM-SIV (2), 1 iteration Argon2
	profileJSON := `{
		"id": 140,
		"cipher": 2,
		"kdf": 0,
		"kdf_iterations": 1,
		"kdf_memory": 16384,
		"kdf_threads": 4,
		"salt_size": 16,
		"nonce_size": 12
	}`
	if err := os.WriteFile(profileFile, []byte(profileJSON), 0644); err != nil {
		t.Fatal(err)
	}

	keyBase := filepath.Join(tmpDir, "custom_id")
	passphrase := "strong-protection"

	// 1. Keygen with custom profile protection
	genCmd := commands.KeygenCmd()
	genCmd.SetArgs([]string{"-o", keyBase, "-s", passphrase, "--profile-file", profileFile})
	if err := genCmd.Execute(); err != nil {
		t.Fatalf("Custom profile keygen failed: %v", err)
	}

	// 2. Encrypt with protected key
	inputFile := filepath.Join(tmpDir, "protected_test.txt")
	if err := os.WriteFile(inputFile, []byte("Encrypted with custom-profile-protected key"), 0644); err != nil {
		t.Fatal(err)
	}
	encryptedFile := inputFile + ".makn"

	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "--public-key", keyBase + ".kem.pub", "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Encryption with protected key failed: %v", err)
	}

	// 3. Decrypt (will need passphrase to unlock private key)
	decryptedFile := filepath.Join(tmpDir, "protected_restored.txt")
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "-k", keyBase + ".kem.key", "-s", passphrase, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Decryption with protected key failed: %v", err)
	}

	// 4. Verify
	restored, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != "Encrypted with custom-profile-protected key" {
		t.Fatalf("Protected key restored content mismatch")
	}
}

func TestIntegrationRandomProfileStress(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Generate a random profile
	profileFile := filepath.Join(tmpDir, "random_profile.json")
	profCmd := commands.ProfilesCmd()
	profCmd.SetArgs([]string{"--generate", "--secret", "--output", profileFile})

	if err := profCmd.Execute(); err != nil {
		t.Fatalf("Random profile generation failed: %v", err)
	}

	inputFile := filepath.Join(tmpDir, "random_test.txt")
	content := []byte("Stress testing randomized cryptographic parameters")
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatal(err)
	}
	encryptedFile := inputFile + ".makn"
	passphrase := "random-pass-123"

	// 2. Encrypt
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", passphrase, "--profile-file", profileFile, "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Random profile encryption failed: %v", err)
	}

	// 3. Decrypt
	decryptedFile := filepath.Join(tmpDir, "random_restored.txt")
	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", decryptedFile, "-s", passphrase, "--profile-file", profileFile, "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Random profile decryption failed: %v", err)
	}

	// 4. Verify
	restored, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, restored) {
		t.Fatalf("Random profile restored content mismatch")
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
	if err := os.WriteFile(profileFile, []byte(profileJSON), 0644); err != nil {
		t.Fatal(err)
	}

	inputFile := filepath.Join(tmpDir, "siv_test.txt")
	content := []byte("AES-GCM-SIV Nonce-Misuse Resistance Test")
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatal(err)
	}

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
	restored, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
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
	if err := os.WriteFile(profileFile, []byte(profileJSON), 0644); err != nil {
		t.Fatal(err)
	}

	inputFile := filepath.Join(tmpDir, "portable_test.txt")
	content := []byte("Portable Profile Content (Packed in Header)")
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatal(err)
	}

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
	restored, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
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
	if err := os.WriteFile(profileFile, []byte(profileJSON), 0644); err != nil {
		t.Fatal(err)
	}

	inputFile := filepath.Join(tmpDir, "secret_test.txt")
	content := []byte("Secret Profile Content")
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatal(err)
	}

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
	restored, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, restored) {
		t.Fatalf("Secret profile restored content mismatch")
	}
}

func TestIntegrationProfileV2(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "v2_test.txt")
	content := []byte("AES-GCM Profile Agility Test Content")
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatal(err)
	}

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
	restored, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
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
	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

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
		_ = wOut.Close()
		os.Stdout = oldStdout
		t.Fatalf("Pipe decryption failed: %v", err)
	}
	if err := wOut.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = oldStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, rOut); err != nil {
		t.Fatal(err)
	}
	if buf.String() != content {
		t.Errorf("Pipe output mismatch. Got: %s, Want: %s", buf.String(), content)
	}
}

func TestIntegrationInfo(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "info_test.txt")
	if err := os.WriteFile(inputFile, []byte("Metadata test data"), 0644); err != nil {
		t.Fatal(err)
	}

	encryptedFile := inputFile + ".makn"
	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{inputFile, "-o", encryptedFile, "-s", "pass", "--compress", "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatal(err)
	}

	// Test Text Output
	output := runRootCmd("info", encryptedFile)
	if !strings.Contains(output, "Symmetric") || !strings.Contains(output, "Compression:    true") {
		t.Errorf("Info text output mismatch. Got: %s", output)
	}

	// Test JSON Output
	outputJSON := runRootCmd("--json", "info", encryptedFile)
	if !strings.Contains(outputJSON, `"type":"symmetric"`) || !strings.Contains(outputJSON, `"compressed":true`) {
		t.Errorf("Info JSON output mismatch. Got: %s", outputJSON)
	}
}

func TestIntegrationIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)

	// 1. Generate an identity
	keyBase := "test_id"
	runRootCmd("keygen", "-o", keyBase, "--no-password")

	// 2. List identities
	output := runRootCmd("identity", "list")
	if !strings.Contains(output, keyBase) {
		t.Errorf("Identity list mismatch. Got: %s", output)
	}

	// 3. Test 'active' command (Identity Discovery)
	outputActive := runRootCmd("identity", "active", "--json")
	if !strings.Contains(outputActive, "test_id.kem.pub") {
		t.Errorf("Identity active discovery failed. Output: %s", outputActive)
	}

	// 4. Rename identity
	newBase := "renamed_id"
	runRootCmd("identity", "rename", keyBase, newBase)

	outputNew := runRootCmd("identity", "list")
	if !strings.Contains(outputNew, newBase) || strings.Contains(outputNew, keyBase) {
		t.Errorf("Identity rename failed. List output: %s", outputNew)
	}
}

func TestIntegrationMultiRecipient(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Generate two identities
	key1 := filepath.Join(tmpDir, "user1")
	key2 := filepath.Join(tmpDir, "user2")
	runRootCmd("keygen", "-o", key1, "--no-password")
	runRootCmd("keygen", "-o", key2, "--no-password")

	inputFile := filepath.Join(tmpDir, "team_secret.txt")
	content := []byte("Top secret team data")
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatal(err)
	}
	encryptedFile := inputFile + ".makn"

	// 2. Encrypt for BOTH recipients
	runRootCmd("encrypt", inputFile, "-o", encryptedFile, "-p", key1+".kem.pub", "-p", key2+".kem.pub", "--quiet")

	// 3. Verify User 1 can decrypt
	out1 := filepath.Join(tmpDir, "restored1.txt")
	runRootCmd("decrypt", encryptedFile, "-o", out1, "-k", key1+".kem.key", "--quiet")
	res1, _ := os.ReadFile(out1)
	if !bytes.Equal(res1, content) {
		t.Errorf("User 1 decryption failed")
	}

	// 4. Verify User 2 can decrypt
	out2 := filepath.Join(tmpDir, "restored2.txt")
	runRootCmd("decrypt", encryptedFile, "-o", out2, "-k", key2+".kem.key", "--quiet")
	res2, _ := os.ReadFile(out2)
	if !bytes.Equal(res2, content) {
		t.Errorf("User 2 decryption failed")
	}
}

func TestIntegrationVaultMaintenance(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)

	vaultName := "maint_test"
	if err := os.Setenv("MAKNOON_PASSWORD", "secret123"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("MAKNOON_PASSWORD")

	// 1. Create vault
	runRootCmd("vault", "set", "svc1", "--vault", vaultName, "--passphrase", "master")

	// 2. Rename vault
	newName := "renamed_vault"
	runRootCmd("vault", "rename", vaultName, newName)

	// 3. Verify access to renamed vault
	output := runRootCmd("vault", "get", "svc1", "--vault", newName, "--passphrase", "master")
	if !strings.Contains(output, "secret123") {
		t.Errorf("Vault maintenance rename failed. Output: %s", output)
	}

	// 4. Delete vault
	// We use JSON mode to skip interactive confirmation
	runRootCmd("--json", "vault", "delete", newName)

	home, _ := os.UserHomeDir()
	dbPath := filepath.Join(home, ".maknoon", "vaults", newName+".db")
	if _, err := os.Stat(dbPath); err == nil {
		t.Errorf("Vault deletion failed, file still exists")
	}
}

func TestIntegrationSignThenEncrypt(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Generate identity
	keyBase := filepath.Join(tmpDir, "sender")
	runRootCmd("keygen", "-o", keyBase, "--no-password")

	inputFile := filepath.Join(tmpDir, "signed_msg.txt")
	content := []byte("Signed and encrypted message")
	if err := os.WriteFile(inputFile, content, 0644); err != nil {
		t.Fatal(err)
	}
	encryptedFile := inputFile + ".makn"

	// 2. Encrypt with integrated signature
	encOut := runRootCmd("encrypt", inputFile, "-o", encryptedFile, "-p", keyBase+".kem.pub", "--sign-key", keyBase+".sig.key", "--quiet")
	if strings.Contains(encOut, `"error":`) {
		t.Fatalf("Encryption failed: %s", encOut)
	}

	// 3. Verify and Decrypt
	restoredFile := filepath.Join(tmpDir, "restored_signed.txt")
	// Must provide --sender-key for verification
	decOut := runRootCmd("decrypt", encryptedFile, "-o", restoredFile, "-k", keyBase+".kem.key", "--sender-key", keyBase+".sig.pub", "--quiet")
	if strings.Contains(decOut, `"error":`) {
		t.Fatalf("Decryption failed: %s", decOut)
	}

	res, err := os.ReadFile(restoredFile)
	if err != nil {
		t.Fatalf("Failed to read restored file: %v", err)
	}
	if !bytes.Equal(res, content) {
		t.Errorf("Integrated sign-then-encrypt content mismatch. Got: %q, Want: %q", string(res), string(content))
	}
}
func TestIntegrationVerbose(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "verbose_test.txt")
	os.WriteFile(inputFile, []byte("Verbose test data"), 0644)

	encryptedFile := inputFile + ".makn"

	// Run with --verbose and check for slog output (contains keywords like "level=INFO" or "msg=")
	output := runRootCmd("encrypt", inputFile, "-o", encryptedFile, "-s", "pass", "--verbose")

	if !strings.Contains(output, "level=INFO") || !strings.Contains(output, "starting symmetric encryption") {
		t.Errorf("Verbose output missing slog traces. Got: %s", output)
	}
}

func TestIntegrationFullFeatureStress(t *testing.T) {
	tmpDir := t.TempDir()

	srcDir := filepath.Join(tmpDir, "complex_source")
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "data.bin"), bytes.Repeat([]byte{0x42}, 100000), 0644); err != nil {
		t.Fatal(err)
	}

	keyBase := filepath.Join(tmpDir, "id_complex")
	genCmd := commands.KeygenCmd()
	genCmd.SetArgs([]string{"-o", keyBase, "--no-password"})
	if err := genCmd.Execute(); err != nil {
		t.Fatalf("Keygen failed: %v", err)
	}

	encryptedFile := filepath.Join(tmpDir, "complex.makn")
	restoredDir := filepath.Join(tmpDir, "complex_restored")

	encCmd := commands.EncryptCmd()
	encCmd.SetArgs([]string{srcDir, "-o", encryptedFile, "--public-key", keyBase + ".kem.pub", "--compress", "--quiet"})
	if err := encCmd.Execute(); err != nil {
		t.Fatalf("Full-feature encryption failed: %v", err)
	}

	decCmd := commands.DecryptCmd()
	decCmd.SetArgs([]string{encryptedFile, "-o", restoredDir, "--private-key", keyBase + ".kem.key", "--quiet"})
	if err := decCmd.Execute(); err != nil {
		t.Fatalf("Full-feature decryption failed: %v", err)
	}

	orig, err := os.ReadFile(filepath.Join(srcDir, "data.bin"))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(filepath.Join(restoredDir, "complex_source", "data.bin"))
	if err != nil {
		t.Fatalf("Failed to read restored file: %v", err)
	}
	if !bytes.Equal(orig, restored) {
		t.Fatalf("Stress test content mismatch")
	}
}
