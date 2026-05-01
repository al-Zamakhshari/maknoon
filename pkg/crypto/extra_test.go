package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestProtectFullFlow(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "maknoon-full-flow-*")
	defer os.RemoveAll(tmpDir)

	srcFile := filepath.Join(tmpDir, "source.txt")
	content := []byte("Full protection pipeline test data")
	_ = os.WriteFile(srcFile, content, 0644)

	passphrase := []byte("standard-pass")
	var encrypted bytes.Buffer

	// Protect with Compression
	_, err := Protect(srcFile, nil, &encrypted, Options{
		Passphrase: passphrase,
		Compress:   BoolPtr(true),
	})
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}

	// Unprotect
	var decrypted bytes.Buffer
	_, err = Unprotect(&encrypted, &decrypted, "", Options{
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("Unprotect failed: %v", err)
	}

	if !bytes.Equal(decrypted.Bytes(), content) {
		t.Errorf("Decrypted data mismatch. Got: %s", decrypted.String())
	}
}

func TestVaultSealOpenConsistency(t *testing.T) {
	masterKey := make([]byte, 32)
	entry := &VaultEntry{
		Service:  "github.com",
		Username: "user1",
		Password: []byte("pass"),
		Note:     "test note",
	}

	ciphertext, err := SealEntry(entry, masterKey)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	restored, err := OpenEntry(ciphertext, masterKey)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if restored.Service != entry.Service || !bytes.Equal(restored.Password, entry.Password) {
		t.Errorf("Mismatch. Got %v, want %v", restored, entry)
	}
}
