package crypto

import (
	"bytes"
	"testing"
)

func TestSymmetricRoundTrip(t *testing.T) {
	data := []byte("This is a secret message for symmetric test.")
	passphrase := []byte("correct-passphrase-123")

	// 1. Encrypt
	var encrypted bytes.Buffer
	if err := EncryptStream(bytes.NewReader(data), &encrypted, passphrase, FlagNone, 0, 0); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 2. Decrypt
	var decrypted bytes.Buffer
	if _, _, err := DecryptStream(bytes.NewReader(encrypted.Bytes()), &decrypted, passphrase, 0, false); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(data, decrypted.Bytes()) {
		t.Errorf("Decrypted data mismatch. Got %s, want %s", decrypted.String(), string(data))
	}

	// 3. Wrong passphrase should fail
	var decryptedWrong bytes.Buffer
	if _, _, err := DecryptStream(bytes.NewReader(encrypted.Bytes()), &decryptedWrong, []byte("wrong-pass"), 0, false); err == nil {
		t.Error("Expected error with wrong passphrase, got nil")
	}
}

func TestAsymmetricRoundTrip(t *testing.T) {
	data := []byte("Post-Quantum Asymmetric Encryption Test Data")
	profile := DefaultProfile()
	priv, pub, err := profile.GenerateHybridKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := pub.Bytes()
	privBytes, _ := priv.Bytes()

	// 1. Encrypt
	var encrypted bytes.Buffer
	if err := EncryptStreamWithPublicKey(bytes.NewReader(data), &encrypted, pubBytes, FlagNone, 0, 0); err != nil {
		t.Fatalf("Asymmetric encryption failed: %v", err)
	}

	// 2. Decrypt
	var decrypted bytes.Buffer
	if _, _, err := DecryptStreamWithPrivateKey(bytes.NewReader(encrypted.Bytes()), &decrypted, privBytes, 0, false); err != nil {
		t.Fatalf("Asymmetric decryption failed: %v", err)
	}

	if !bytes.Equal(data, decrypted.Bytes()) {
		t.Errorf("Asymmetric mismatch. Got %s, want %s", decrypted.String(), string(data))
	}
}

func TestIntegratedSignThenEncryptUnit(t *testing.T) {
	data := []byte("Sign-then-Encrypt Unit Test")
	profile := DefaultProfile()

	// Recipient keys
	priv, pub, _ := profile.GenerateHybridKeyPair()
	pubBytes := pub.Bytes()
	privBytes, _ := priv.Bytes()
	// Sender keys
	spub, spriv, _ := profile.GenerateSIGKeyPair()

	// 1. Encrypt with integrated signature
	var encrypted bytes.Buffer
	if err := EncryptStreamWithPublicKeysAndSigner(bytes.NewReader(data), &encrypted, [][]byte{pubBytes}, spriv, FlagNone, 0, 0); err != nil {
		t.Fatalf("Integrated encryption failed: %v", err)
	}

	// 2. Decrypt and Verify
	var decrypted bytes.Buffer
	// Test failure without sender key
	_, _, err = DecryptStreamWithPrivateKey(bytes.NewReader(encrypted.Bytes()), &decrypted, privBytes, 0, false)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("sender public key not provided")) {
		t.Errorf("Expected error for missing sender key, got: %v", err)
	}

	// Test success with sender key
	decrypted.Reset()
	_, _, err = DecryptStreamWithPrivateKeyAndVerifier(bytes.NewReader(encrypted.Bytes()), &decrypted, privBytes, spub, 0, false)
	if err != nil {
		t.Fatalf("Integrated decryption failed: %v", err)
	}

	if !bytes.Equal(data, decrypted.Bytes()) {
		t.Errorf("Content mismatch. Got %q", decrypted.String())
	}
}

func TestDecryptEdgeCases(t *testing.T) {
	passphrase := []byte("correct-passphrase-123")

	tests := []struct {
		name        string
		input       []byte
		expectError bool
	}{
		{"Empty Input", []byte{}, true},
		{"Incomplete Header", []byte("MAK"), true},
		{"Wrong Magic", []byte("BADN\x01\x00"), true},
		{"Truncated Salt", []byte("MAKN\x01\x0012345"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var decrypted bytes.Buffer
			_, _, err := DecryptStream(bytes.NewReader(tc.input), &decrypted, passphrase, 1, false)
			if (err != nil) != tc.expectError {
				t.Fatalf("Expected error: %v, got: %v", tc.expectError, err)
			}
		})
	}
}

func TestEncryptEdgeCases(t *testing.T) {
	// Zero-byte inputs
	var encrypted bytes.Buffer
	err := EncryptStream(bytes.NewReader([]byte{}), &encrypted, []byte("pass"), FlagNone, 1, 0)
	if err != nil {
		t.Fatalf("Zero-byte encryption failed: %v", err)
	}

	var decrypted bytes.Buffer
	_, _, err = DecryptStream(bytes.NewReader(encrypted.Bytes()), &decrypted, []byte("pass"), 1, false)
	if err != nil {
		t.Fatalf("Zero-byte decryption failed: %v", err)
	}

	if len(decrypted.Bytes()) != 0 {
		t.Fatalf("Expected empty output, got %d bytes", len(decrypted.Bytes()))
	}
}

func TestStealthSymmetricRoundTrip(t *testing.T) {
	data := []byte("Stealth Symmetric Test")
	passphrase := []byte("stealth-pass-123")

	// 1. Encrypt with Stealth
	var encrypted bytes.Buffer
	err := EncryptStream(bytes.NewReader(data), &encrypted, passphrase, FlagStealth, 1, 0)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify no magic bytes
	if bytes.HasPrefix(encrypted.Bytes(), []byte(MagicHeader)) {
		t.Error("Security failure: MagicHeader found in stealth ciphertext")
	}

	// 2. Decrypt with Stealth
	var decrypted bytes.Buffer
	_, _, err = DecryptStream(bytes.NewReader(encrypted.Bytes()), &decrypted, passphrase, 1, true)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(data, decrypted.Bytes()) {
		t.Errorf("Content mismatch. Got %q", decrypted.String())
	}
}

func TestStealthAsymmetricRoundTrip(t *testing.T) {
	data := []byte("Stealth Asymmetric Test")
	profile := DefaultProfile()
	priv, pub, err := profile.GenerateHybridKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := pub.Bytes()
	privBytes, _ := priv.Bytes()

	// 1. Encrypt with Stealth
	var encrypted bytes.Buffer
	err = EncryptStreamWithPublicKey(bytes.NewReader(data), &encrypted, pubBytes, FlagStealth, 1, 0)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify no magic bytes
	if bytes.HasPrefix(encrypted.Bytes(), []byte(MagicHeaderAsym)) {
		t.Error("Security failure: MagicHeaderAsym found in stealth ciphertext")
	}

	// 2. Decrypt with Stealth
	var decrypted bytes.Buffer
	_, _, err = DecryptStreamWithPrivateKey(bytes.NewReader(encrypted.Bytes()), &decrypted, privBytes, 1, true)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(data, decrypted.Bytes()) {
		t.Errorf("Content mismatch. Got %q", decrypted.String())
	}
}

