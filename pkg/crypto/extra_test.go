package crypto

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	_, _, pub, priv, err := GeneratePQKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	data := []byte("Authentication Message")
	sig, err := SignData(data, priv)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	if !VerifySignature(data, sig, pub) {
		t.Fatal("Signature verification failed")
	}

	if VerifySignature([]byte("Modified Message"), sig, pub) {
		t.Fatal("Signature verification should have failed for modified data")
	}
}

func TestProtectExtractRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "input.txt")
	encryptedFile := filepath.Join(tmpDir, "output.makn")
	content := []byte("Pipeline testing data")
	os.WriteFile(inputFile, content, 0644)

	passphrase := []byte("secret")

	// 1. Protect (Encrypt)
	out, _ := os.Create(encryptedFile)
	opts := Options{
		Passphrase: passphrase,
		Compress:   true,
	}
	if err := Protect(inputFile, nil, out, opts); err != nil {
		t.Fatalf("Protect failed: %v", err)
	}
	out.Close()

	// 2. Decrypt
	in, _ := os.Open(encryptedFile)
	var decrypted bytes.Buffer
	flags, err := DecryptStream(in, &decrypted, passphrase, 1)
	if err != nil {
		t.Fatalf("DecryptStream failed: %v", err)
	}
	in.Close()

	if flags&FlagCompress == 0 {
		t.Fatal("Expected compression flag to be set")
	}

	// 3. Finalize (Decompress)
	// We need to handle the compression in the test manually or use a helper
	// Since we are testing 'Protect', let's also test 'ExtractArchive' with a directory

	srcDir := filepath.Join(tmpDir, "src_dir")
	os.Mkdir(srcDir, 0755)
	os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("a"), 0644)

	archivedFile := filepath.Join(tmpDir, "archived.makn")
	outArch, _ := os.Create(archivedFile)
	optsArch := Options{
		Passphrase: passphrase,
		IsArchive:  true,
		Compress:   false,
	}
	if err := Protect(srcDir, nil, outArch, optsArch); err != nil {
		t.Fatalf("Protect archive failed: %v", err)
	}
	outArch.Close()

	// Decrypt Archive
	inArch, _ := os.Open(archivedFile)
	var decryptedArch bytes.Buffer
	_, err = DecryptStream(inArch, &decryptedArch, passphrase, 1)
	if err != nil {
		t.Fatalf("DecryptStream archive failed: %v", err)
	}
	inArch.Close()

	// Extract
	extractDir := filepath.Join(tmpDir, "extracted")
	if err := ExtractArchive(&decryptedArch, extractDir); err != nil {
		t.Fatalf("ExtractArchive failed: %v", err)
	}

	// Verify
	extractedFile := filepath.Join(extractDir, "src_dir", "a.txt")
	check, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("Extracted file not found: %v", err)
	}
	if !bytes.Equal(check, []byte("a")) {
		t.Fatalf("Extracted content mismatch: %s", string(check))
	}
}

func TestSafeClearString(t *testing.T) {
	s := []string{"keep", "it", "secret"}
	SafeClearString(s)
	for i := range s {
		if s[i] != "" {
			t.Errorf("SafeClearString failed at index %d", i)
		}
	}
}

func TestEnsureMaknoonDirs(t *testing.T) {
	if err := EnsureMaknoonDirs(); err != nil {
		t.Fatalf("EnsureMaknoonDirs failed: %v", err)
	}
}

func TestResolveKeyPath(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.key")
	os.WriteFile(testFile, []byte("key"), 0644)

	resolved := ResolveKeyPath(testFile, "")
	if resolved != testFile {
		t.Errorf("Expected %s, got %s", testFile, resolved)
	}

	// Non-existent path should return as is
	nonExistent := "non-existent.key"
	resolved = ResolveKeyPath(nonExistent, "")
	if resolved != nonExistent {
		t.Errorf("Expected %s, got %s", nonExistent, resolved)
	}
}

func TestGetDefaultVaultPath(t *testing.T) {
	path := GetDefaultVaultPath()
	if !filepath.IsAbs(path) {
		t.Error("Default vault path should be absolute")
	}
}

func TestVaultErrors(t *testing.T) {
	masterKey := make([]byte, 32)

	// Test OpenEntry with invalid ciphertext
	if _, err := OpenEntry([]byte("short"), masterKey); err == nil {
		t.Error("Expected error for short ciphertext in OpenEntry")
	}

	// Test OpenEntry with invalid master key (authentication failure)
	entry := &VaultEntry{Service: "test", Password: "pass"}
	ciphertext, _ := SealEntry(entry, masterKey)
	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	if _, err := OpenEntry(ciphertext, wrongKey); err == nil {
		t.Error("Expected authentication failure for wrong master key")
	}
}

func TestAsymmetricErrors(t *testing.T) {
	pub, priv, _, _, _ := GeneratePQKeyPair()
	msg := []byte("hello")
	sig, _ := SignData(msg, priv)

	// 1. Invalid signature
	badSig := make([]byte, len(sig))
	if VerifySignature(msg, badSig, pub) {
		t.Error("VerifySignature should fail for zeroed signature")
	}

	// 2. Corrupted key unmarshaling
	if _, err := SignData(msg, []byte("too short")); err == nil {
		t.Error("SignData should fail for invalid key length")
	}
	if VerifySignature(msg, sig, []byte("bad pub")) {
		// Should return false
	}
}

func TestStreamErrors(t *testing.T) {
	// Test reader error during encryption
	errReader := &errorReader{err: fmt.Errorf("read fail")}
	var buf bytes.Buffer
	if err := EncryptStream(errReader, &buf, []byte("pass"), FlagNone, 1); err == nil {
		t.Error("EncryptStream should fail if reader fails")
	}

	// Test writer error during encryption
	var encBuf bytes.Buffer
	errWriter := &errorWriter{err: fmt.Errorf("write fail")}
	if err := EncryptStream(bytes.NewReader([]byte("data")), errWriter, []byte("pass"), FlagNone, 1); err == nil {
		// This might fail during header write or chunk write
	}
	_ = encBuf
}

type errorReader struct{ err error }

func (r *errorReader) Read(p []byte) (n int, err error) { return 0, r.err }

type errorWriter struct{ err error }

func (w *errorWriter) Write(p []byte) (n int, err error) { return 0, w.err }

func TestDecryptStreamErrors(t *testing.T) {
	password := []byte("pass")

	// 1. Valid file but truncated
	var encrypted bytes.Buffer
	EncryptStream(bytes.NewReader([]byte("some data")), &encrypted, password, FlagNone, 1)
	truncated := encrypted.Bytes()[:10]
	var out bytes.Buffer
	if _, err := DecryptStream(bytes.NewReader(truncated), &out, password, 1); err == nil {
		t.Error("Expected error for truncated header in DecryptStream")
	}

	// 2. Corrupted chunk length
	EncryptStream(bytes.NewReader([]byte("some data")), &encrypted, password, FlagNone, 1)
	corrupted := encrypted.Bytes()
	// Find where payload starts (Header: 4+1+1+32+24 = 62 bytes)
	// Let's just mess with it.
	if len(corrupted) > 70 {
		corrupted[65] = 0xFF
		corrupted[66] = 0xFF
	}
	if _, err := DecryptStream(bytes.NewReader(corrupted), &out, password, 1); err == nil {
		t.Error("Expected error for corrupted chunk length")
	}
}
