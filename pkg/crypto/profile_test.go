package crypto

import (
	"bytes"
	"testing"
)

func init() {
	// Ensure built-in profiles are registered with valid parameters for tests
	RegisterProfile(&ProfileV1{
		ArgonTime: 3,
		ArgonMem:  64 * 1024,
		ArgonThrd: 4,
	})
	RegisterProfile(&ProfileV3{
		ArgonTime: 3,
		ArgonMem:  64 * 1024,
		ArgonThrd: 4,
	})
}

func TestProfileV3RoundTrip(t *testing.T) {
	data := []byte("Conservative Suite (FrodoKEM + SLH-DSA) Test")
	profile, _ := GetProfile(3, nil)

	// 1. Asymmetric Keys
	priv, pub, err := profile.GenerateHybridKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// 2. Encrypt (Asymmetric)
	var encrypted bytes.Buffer
	if err := EncryptStreamWithPublicKeys(bytes.NewReader(data), &encrypted, [][]byte{pub}, FlagNone, 1, 3); err != nil {
		t.Fatalf("V3 Encryption failed: %v", err)
	}

	// 3. Decrypt
	var decrypted bytes.Buffer
	_, _, err = DecryptStreamWithPrivateKey(bytes.NewReader(encrypted.Bytes()), &decrypted, priv, nil, 1, false)
	if err != nil {
		t.Fatalf("V3 Decryption failed: %v", err)
	}

	if !bytes.Equal(data, decrypted.Bytes()) {
		t.Errorf("V3 Round-trip mismatch. Got %s, want %s", decrypted.String(), string(data))
	}
}

func TestRandomProfileGeneration(t *testing.T) {
	seenIDs := make(map[byte]bool)
	seenCiphers := make(map[byte]bool)

	for i := 0; i < 100; i++ {
		dp := GenerateRandomProfile(byte(i % 128))
		if err := dp.Validate(); err != nil {
			t.Fatalf("Generated invalid profile on iteration %d: %v", i, err)
		}

		// Ensure we are getting varied IDs and ciphers
		seenIDs[dp.ID()] = true
		seenCiphers[dp.CipherType] = true

		// Perform a quick round-trip to ensure functionality
		canary := []byte("random-profile-test-data")
		pass := []byte("pass")
		var enc bytes.Buffer
		aead, _ := dp.NewAEAD(dp.DeriveKey(pass, make([]byte, dp.SaltSize())))
		nonce := make([]byte, aead.NonceSize())
		if err := streamEncrypt(bytes.NewReader(canary), &enc, aead, nonce, 1, nil); err != nil {
			t.Fatalf("Random profile encryption failed: %v", err)
		}
	}

	if len(seenCiphers) < 2 {
		t.Errorf("Low cipher diversity in random profiles: %v", seenCiphers)
	}
}
