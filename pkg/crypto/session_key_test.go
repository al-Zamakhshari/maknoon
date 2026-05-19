package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveSessionKeyLength(t *testing.T) {
	key, salt, err := DeriveSessionKey([]byte("test-passphrase"))
	if err != nil {
		t.Fatalf("DeriveSessionKey: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
	if len(salt) == 0 {
		t.Error("salt is empty")
	}
}

func TestDeriveSessionKeyUniqueSalt(t *testing.T) {
	// Each call generates a fresh random salt → different keys.
	k1, s1, _ := DeriveSessionKey([]byte("same-passphrase"))
	k2, s2, _ := DeriveSessionKey([]byte("same-passphrase"))
	if bytes.Equal(s1, s2) {
		t.Error("two DeriveSessionKey calls produced identical salts")
	}
	if bytes.Equal(k1, k2) {
		t.Error("two DeriveSessionKey calls with different salts produced identical keys")
	}
}

func TestRederiveSessionKeyDeterministic(t *testing.T) {
	pass := []byte("deterministic-pass")
	key1, salt, err := DeriveSessionKey(pass)
	if err != nil {
		t.Fatalf("DeriveSessionKey: %v", err)
	}
	key2, err := RederiveSessionKey(pass, salt)
	if err != nil {
		t.Fatalf("RederiveSessionKey: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Error("RederiveSessionKey with same pass+salt produced different key")
	}
}

func TestRederiveSessionKeyWrongSaltLength(t *testing.T) {
	_, err := RederiveSessionKey([]byte("pass"), []byte("tooshort"))
	if err == nil {
		t.Error("expected error for wrong salt length")
	}
}

func TestEncryptDecryptStreamWithKey(t *testing.T) {
	pass := []byte("session-key-enc-dec")
	key, salt, _ := DeriveSessionKey(pass)

	plaintext := []byte("session key encryption round-trip test payload")
	var ciphertext bytes.Buffer
	if err := EncryptStreamWithKey(bytes.NewReader(plaintext), &ciphertext, key, salt, 0, 1, 0); err != nil {
		t.Fatalf("EncryptStreamWithKey: %v", err)
	}

	var recovered bytes.Buffer
	_, _, err := DecryptStreamWithKey(bytes.NewReader(ciphertext.Bytes()), &recovered, key, 1, false)
	if err != nil {
		t.Fatalf("DecryptStreamWithKey: %v", err)
	}
	if !bytes.Equal(recovered.Bytes(), plaintext) {
		t.Errorf("round-trip mismatch\ngot:  %q\nwant: %q", recovered.Bytes(), plaintext)
	}
}

func TestEncryptStreamWithKeyBadKeyLength(t *testing.T) {
	err := EncryptStreamWithKey(bytes.NewReader([]byte("x")), &bytes.Buffer{}, []byte("short"), nil, 0, 1, 0)
	if err == nil {
		t.Error("expected error for key shorter than 32 bytes")
	}
}

func TestEncryptStreamWithKeyProducesUniqueCiphertext(t *testing.T) {
	key, salt, _ := DeriveSessionKey([]byte("unique-ct"))
	plaintext := []byte("same plaintext")

	var ct1, ct2 bytes.Buffer
	EncryptStreamWithKey(bytes.NewReader(plaintext), &ct1, key, salt, 0, 1, 0)
	EncryptStreamWithKey(bytes.NewReader(plaintext), &ct2, key, salt, 0, 1, 0)

	// Random base nonce → different ciphertext each time.
	if bytes.Equal(ct1.Bytes(), ct2.Bytes()) {
		t.Error("two encryptions of the same plaintext produced identical ciphertext")
	}
}

func TestSessionKeyEncryptWithDiscard(t *testing.T) {
	// DecryptStreamWithKey with nil writer should not panic and should use io.Discard.
	key, salt, _ := DeriveSessionKey([]byte("discard-test"))
	var ct bytes.Buffer
	EncryptStreamWithKey(bytes.NewReader([]byte("drop me")), &ct, key, salt, 0, 1, 0)
	_, _, err := DecryptStreamWithKey(bytes.NewReader(ct.Bytes()), nil, key, 1, false)
	if err != nil {
		t.Errorf("DecryptStreamWithKey with nil writer: %v", err)
	}
}
