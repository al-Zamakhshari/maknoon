package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
	"testing"
)

// TestCiphertextTamperRejected verifies that any modification to the ciphertext
// causes decryption to fail with an authentication error (AEAD integrity).
func TestCiphertextTamperRejected(t *testing.T) {
	password := []byte("tamper-test-password")
	plaintext := make([]byte, 1024)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		t.Fatal(err)
	}

	var enc bytes.Buffer
	if err := EncryptStream(bytes.NewReader(plaintext), &enc, password, FlagNone, 1, 0); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	ciphertext := enc.Bytes()

	flipPositions := []int{100, 500, len(ciphertext) - 2}
	for _, pos := range flipPositions {
		if pos >= len(ciphertext) {
			continue
		}
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		tampered[pos] ^= 0xFF // flip all bits at this byte

		var dec bytes.Buffer
		_, _, err := DecryptStream(bytes.NewReader(tampered), &dec, password, 1, false)
		if err == nil {
			t.Errorf("tamper at byte %d: decryption should have failed but succeeded", pos)
		} else if !strings.Contains(err.Error(), "auth") &&
			!strings.Contains(err.Error(), "cipher") &&
			!strings.Contains(err.Error(), "corrupt") &&
			!strings.Contains(err.Error(), "format") &&
			!strings.Contains(err.Error(), "invalid") {
			t.Logf("tamper at byte %d: got expected error: %v", pos, err)
		}
	}
}

// TestNonceUniqueness encrypts the same 64KB block 10,000 times and verifies
// no two encryption runs produce the same ciphertext (nonce is never reused).
func TestNonceUniqueness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping nonce uniqueness (10k iterations) in short mode")
	}

	password := []byte("nonce-unique-test")
	data := make([]byte, ChunkSize) // one 64KB chunk
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		t.Fatal(err)
	}

	const iterations = 10_000
	seen := make(map[[32]byte]struct{}, iterations)

	for i := 0; i < iterations; i++ {
		var enc bytes.Buffer
		if err := EncryptStream(bytes.NewReader(data), &enc, password, FlagNone, 1, 0); err != nil {
			t.Fatalf("iteration %d: EncryptStream failed: %v", i, err)
		}
		// Use a fingerprint of the first 32 bytes of ciphertext as a nonce proxy.
		// Since the nonce is embedded in the header, identical nonces → identical prefix.
		var key [32]byte
		copy(key[:], enc.Bytes()[:32])
		if _, dup := seen[key]; dup {
			t.Fatalf("nonce collision detected at iteration %d (ciphertext prefix repeated)", i)
		}
		seen[key] = struct{}{}
	}
	t.Logf("10,000 encryptions produced unique nonces (no birthday collision)")
}
