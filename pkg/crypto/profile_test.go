package crypto

import (
	"bytes"
	"crypto/cipher"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// MockProfileV2 is a lightweight profile for testing.
type MockProfileV2 struct {
	ProfileV1
}

func (p *MockProfileV2) ID() byte { return 2 }

func (p *MockProfileV2) NewAEAD(key []byte) (cipher.AEAD, error) {
	// Use standard ChaCha20-Poly1305 (12-byte nonce) instead of XChaCha20
	return chacha20poly1305.New(key)
}

func (p *MockProfileV2) NonceSize() int { return 12 }

func TestProfileV2RoundTrip(t *testing.T) {
	RegisterProfile(&MockProfileV2{})
	profile, _ := GetProfile(2, nil)

	data := []byte("Testing with 12-byte nonce profile")
	passphrase := []byte("test-pass")

	// 1. Encrypt with Profile V2
	// We need to temporarily force EncryptStream to use v2 or use a lower-level function
	// For now, let's just manually construct what EncryptStream does but with profile V2
	salt := make([]byte, profile.SaltSize())
	key := profile.DeriveKey(passphrase, salt)
	aead, _ := profile.NewAEAD(key)
	baseNonce := make([]byte, aead.NonceSize())

	var encrypted bytes.Buffer
	// Header: Magic | ProfileID | Flags | Salt | BaseNonce
	encrypted.Write([]byte(MagicHeader))
	encrypted.Write([]byte{profile.ID(), FlagNone})
	encrypted.Write(salt)
	encrypted.Write(baseNonce)
	
	headerSize := encrypted.Len()

	if err := streamEncrypt(bytes.NewReader(data), &encrypted, aead, baseNonce, 1); err != nil {
		t.Fatalf("streamEncrypt failed: %v", err)
	}

	// 2. Decrypt (Should auto-detect profile 2)
	var decrypted bytes.Buffer
	// Create a copy of the buffer to read from
	encryptedCopy := bytes.NewReader(encrypted.Bytes())
	_, err := DecryptStream(encryptedCopy, &decrypted, passphrase, 1)
	if err != nil {
		t.Fatalf("Decryption of Profile V2 failed: %v", err)
	}
	_ = headerSize

	if !bytes.Equal(data, decrypted.Bytes()) {
		t.Errorf("Data mismatch. Got %s, want %s", decrypted.String(), string(data))
	}
}

func TestProfileAsymmetricRoundTrip(t *testing.T) {
	profile := DefaultProfile()
	
	// 1. Generate keys through profile
	pub, priv, err := profile.GenerateKEMKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate KEM keys: %v", err)
	}

	data := []byte("Asymmetric agility test")
	
	// 2. Encrypt
	var encrypted bytes.Buffer
	if err := EncryptStreamWithPublicKey(bytes.NewReader(data), &encrypted, pub, FlagNone, 1, 0); err != nil {
		t.Fatalf("EncryptStreamWithPublicKey failed: %v", err)
	}

	// 3. Decrypt
	var decrypted bytes.Buffer
	_, err = DecryptStreamWithPrivateKey(bytes.NewReader(encrypted.Bytes()), &decrypted, priv, 1)
	if err != nil {
		t.Fatalf("DecryptStreamWithPrivateKey failed: %v", err)
	}

	if !bytes.Equal(data, decrypted.Bytes()) {
		t.Errorf("Data mismatch. Got %s, want %s", decrypted.String(), string(data))
	}
}

func TestProfileValidation(t *testing.T) {
	tests := []struct {
		name    string
		dp      DynamicProfile
		wantErr bool
	}{
		{"Valid XChaCha", DynamicProfile{CipherType: AlgoXChaCha20Poly1305, KdfType: KdfArgon2id, ArgonTime: 1, ArgonMem: 1024, CustomSalt: 16, CustomNonc: 24}, false},
		{"Valid AES", DynamicProfile{CipherType: AlgoAES256GCM, KdfType: KdfArgon2id, ArgonTime: 1, ArgonMem: 1024, CustomSalt: 16, CustomNonc: 12}, false},
		{"Invalid Cipher", DynamicProfile{CipherType: 99, KdfType: KdfArgon2id, ArgonTime: 1, ArgonMem: 1024, CustomSalt: 16, CustomNonc: 12}, true},
		{"Invalid Nonce AES", DynamicProfile{CipherType: AlgoAES256GCM, KdfType: KdfArgon2id, ArgonTime: 1, ArgonMem: 1024, CustomSalt: 16, CustomNonc: 24}, true},
		{"Weak Argon Memory", DynamicProfile{CipherType: AlgoAES256GCM, KdfType: KdfArgon2id, ArgonTime: 1, ArgonMem: 512, CustomSalt: 16, CustomNonc: 12}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dp.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMultipleCustomProfiles(t *testing.T) {
	dp1 := &DynamicProfile{CustomID: 10, CipherType: AlgoAES256GCM, KdfType: KdfArgon2id, ArgonTime: 1, ArgonMem: 1024, CustomSalt: 16, CustomNonc: 12}
	dp2 := &DynamicProfile{CustomID: 20, CipherType: AlgoXChaCha20Poly1305, KdfType: KdfArgon2id, ArgonTime: 1, ArgonMem: 1024, CustomSalt: 16, CustomNonc: 24}

	RegisterProfile(dp1)
	RegisterProfile(dp2)

	p1, _ := GetProfile(10, nil)
	p2, _ := GetProfile(20, nil)

	if p1.NonceSize() != 12 || p2.NonceSize() != 24 {
		t.Error("Custom profiles interfered with each other")
	}
}

func TestProfileRegistry(t *testing.T) {
	RegisterProfile(&MockProfileV2{})

	p1, err := GetProfile(1, nil)
	if err != nil {
		t.Fatalf("Failed to get profile 1: %v", err)
	}
	if p1.ID() != 1 {
		t.Errorf("Expected ID 1, got %d", p1.ID())
	}

	p2, err := GetProfile(2, nil)
	if err != nil {
		t.Fatalf("Failed to get profile 2: %v", err)
	}
	if p2.ID() != 2 {
		t.Errorf("Expected ID 2, got %d", p2.ID())
	}

	_, err = GetProfile(99, nil)
	if err == nil {
		t.Error("Expected error for non-existent profile ID 99")
	}
}

func TestDefaultProfile(t *testing.T) {
	p := DefaultProfile()
	if p == nil {
		t.Fatal("Default profile should not be nil")
	}
	if p.ID() != 1 {
		t.Errorf("Expected default ID 1, got %d", p.ID())
	}
}
