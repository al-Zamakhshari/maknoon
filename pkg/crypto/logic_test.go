package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveVaultKey(t *testing.T) {
	password := []byte("pass")
	salt := make([]byte, 32)

	key1 := DeriveVaultKey(password, salt)
	key2 := DeriveVaultKey(password, salt)

	if !bytes.Equal(key1, key2) {
		t.Fatal("Deterministic key derivation failed")
	}

	if len(key1) != 32 {
		t.Errorf("Expected 32-byte key, got %d", len(key1))
	}
}

func TestVaultEntryRoundTrip(t *testing.T) {
	masterKey := make([]byte, 32)
	entry := &VaultEntry{
		Service:  "test",
		Password: "secret-password",
	}

	ciphertext, err := SealEntry(entry, masterKey)
	if err != nil {
		t.Fatal(err)
	}

	restored, err := OpenEntry(ciphertext, masterKey)
	if err != nil {
		t.Fatal(err)
	}

	if restored.Password != entry.Password {
		t.Errorf("Vault round-trip failed. Got %s", restored.Password)
	}
}

func TestCorruptedHeader(t *testing.T) {
	data := []byte("NOT-A-MAKN-FILE-AT-ALL")
	var out bytes.Buffer

	_, err := DecryptStream(bytes.NewReader(data), &out, []byte("pass"))
	if err == nil {
		t.Fatal("Expected error for invalid magic header, but got nil")
	}
}

func TestUnsupportedVersion(t *testing.T) {
	// Magic (4) | Version (1) | ...
	data := []byte("MAKN")
	data = append(data, 99) // Unsupported version 99
	data = append(data, make([]byte, 100)...)

	var out bytes.Buffer
	_, err := DecryptStream(bytes.NewReader(data), &out, []byte("pass"))
	if err == nil {
		t.Fatal("Expected error for unsupported version, but got nil")
	}
}

func TestSafeClear(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	SafeClear(b)
	for i := range b {
		if b[i] != 0 {
			t.Errorf("SafeClear failed to zero out index %d", i)
		}
	}
}
