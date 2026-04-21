package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func init() {
	// Ensure built-in profiles are registered with valid parameters for tests
	RegisterProfile(&ProfileV1{
		ArgonTime: 3,
		ArgonMem:  64 * 1024,
		ArgonThrd: 4,
	})
	RegisterProfile(&ProfileV2{
		ProfileV1: ProfileV1{
			ArgonTime: 3,
			ArgonMem:  64 * 1024,
			ArgonThrd: 4,
		},
	})
}

func TestProfileV2RoundTrip(t *testing.T) {
	data := []byte("High Compatibility Suite (AES-GCM) Test")
	passphrase := []byte("aes-gcm-pass")
	profile, _ := GetProfile(2, nil)

	// Encrypt
	var encrypted bytes.Buffer
	encrypted.Write([]byte(MagicHeader))
	encrypted.Write([]byte{profile.ID(), FlagNone})

	salt := make([]byte, profile.SaltSize())
	_, _ = io.ReadFull(rand.Reader, salt)
	encrypted.Write(salt)

	key := profile.DeriveKey(passphrase, salt)
	aead, _ := profile.NewAEAD(key)
	baseNonce := make([]byte, aead.NonceSize())
	_, _ = io.ReadFull(rand.Reader, baseNonce)
	encrypted.Write(baseNonce)

	if err := streamEncrypt(bytes.NewReader(data), &encrypted, aead, baseNonce, 1); err != nil {
		t.Fatal(err)
	}

	// Decrypt
	var decrypted bytes.Buffer
	_, _, err := DecryptStream(bytes.NewReader(encrypted.Bytes()), &decrypted, passphrase, 1, false)
	if err != nil {
		t.Fatalf("V2 Decryption failed: %v", err)
	}

	if !bytes.Equal(data, decrypted.Bytes()) {
		t.Errorf("V2 Round-trip mismatch")
	}
}
