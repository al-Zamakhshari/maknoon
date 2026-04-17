package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestSymmetricRoundTrip(t *testing.T) {
	password := []byte("secure-test-password")
	originalData := make([]byte, 250*1024) // 250KB (spans multiple 64KB chunks)
	if _, err := io.ReadFull(rand.Reader, originalData); err != nil {
		t.Fatal(err)
	}

	// 1. Encrypt
	var encrypted bytes.Buffer
	err := EncryptStream(bytes.NewReader(originalData), &encrypted, password, FlagNone, 1, 0)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 2. Decrypt
	var decrypted bytes.Buffer
	flags, err := DecryptStream(bytes.NewReader(encrypted.Bytes()), &decrypted, password, 1)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if flags != FlagNone {
		t.Errorf("Expected FlagNone, got %v", flags)
	}

	// 3. Verify
	if !bytes.Equal(originalData, decrypted.Bytes()) {
		t.Fatal("Decrypted data does not match original data")
	}
}

func TestAsymmetricRoundTrip(t *testing.T) {
	// 1. Generate PQ Keypair
	pub, priv, _, _, err := GeneratePQKeyPair()
	if err != nil {
		t.Fatalf("Keygen failed: %v", err)
	}

	originalData := []byte("Post-Quantum Secret Data")

	// 2. Encrypt with Public Key
	var encrypted bytes.Buffer
	err = EncryptStreamWithPublicKey(bytes.NewReader(originalData), &encrypted, pub, FlagNone, 1, 0)
	if err != nil {
		t.Fatalf("Asymmetric encryption failed: %v", err)
	}

	// 3. Decrypt with Private Key
	var decrypted bytes.Buffer
	flags, err := DecryptStreamWithPrivateKey(bytes.NewReader(encrypted.Bytes()), &decrypted, priv, 1)
	if err != nil {
		t.Fatalf("Asymmetric decryption failed: %v", err)
	}

	if flags != FlagNone {
		t.Errorf("Expected FlagNone, got %v", flags)
	}

	// 4. Verify
	if !bytes.Equal(originalData, decrypted.Bytes()) {
		t.Fatal("Decrypted asymmetric data does not match original")
	}
}

func TestEmptyFile(t *testing.T) {
	password := []byte("test")
	originalData := []byte("")

	var encrypted bytes.Buffer
	if err := EncryptStream(bytes.NewReader(originalData), &encrypted, password, FlagNone, 1, 0); err != nil {
		t.Fatal(err)
	}

	var decrypted bytes.Buffer
	if _, err := DecryptStream(bytes.NewReader(encrypted.Bytes()), &decrypted, password, 1); err != nil {
		t.Fatal(err)
	}

	if decrypted.Len() != 0 {
		t.Fatal("Expected empty decryption output for empty input")
	}
}

func TestInvalidPassword(t *testing.T) {
	password := []byte("correct-password")
	wrongPassword := []byte("wrong-password")
	data := []byte("sensitive info")

	var encrypted bytes.Buffer
	if err := EncryptStream(bytes.NewReader(data), &encrypted, password, FlagNone, 1, 0); err != nil {
		t.Fatal(err)
	}

	var decrypted bytes.Buffer
	_, err := DecryptStream(bytes.NewReader(encrypted.Bytes()), &decrypted, wrongPassword, 1)
	if err == nil {
		t.Fatal("Expected error when decrypting with wrong password, but got nil")
	}
}
