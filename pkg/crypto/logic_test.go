package crypto

import (
	"bytes"
	"testing"
)

func TestIntegrationVault(t *testing.T) {
	masterPass := []byte("master-secret-123")
	salt := make([]byte, 32)
	key := DeriveVaultKey(masterPass, salt)

	entry := &VaultEntry{
		Service:  "CloudService",
		Username: "admin",
		Password: []byte("secret-password"),
	}

	// Seal
	ct, err := SealEntry(entry, key)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Open
	restored, err := OpenEntry(ct, key)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if restored.Service != entry.Service || restored.Username != entry.Username {
		t.Errorf("Mismatch in restored metadata")
	}

	if !bytes.Equal(restored.Password, entry.Password) {
		t.Errorf("Mismatch in restored password. Got %s, Want %s", restored.Password, entry.Password)
	}

	// Wrong key should fail
	wrongKey := make([]byte, 32)
	_, err = OpenEntry(ct, wrongKey)
	if err == nil {
		t.Errorf("Expected failure with wrong master key")
	}
}
