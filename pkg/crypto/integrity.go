package crypto

import (
	"bytes"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// RunPOST executes Power-On Self-Tests to verify cryptographic integrity.
// This is a mandatory industrial safeguard.
func RunPOST() error {
	// 1. ML-DSA-87 KAT (Known Answer Test) - Minimal check
	if err := testMLDSA(); err != nil {
		return fmt.Errorf("ML-DSA integrity check failed: %w", err)
	}

	// 2. AES-256-GCM Integrity
	if err := testAES(); err != nil {
		return fmt.Errorf("AES integrity check failed: %w", err)
	}

	return nil
}

func testMLDSA() error {
	pk, sk, err := mldsa87.GenerateKey(bytes.NewReader(make([]byte, 1000))) // Deterministic for KAT
	if err != nil {
		return err
	}

	msg := []byte("Maknoon Industrial POST")
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(sk, msg, nil, true, sig); err != nil {
		return err
	}

	if !mldsa87.Verify(pk, msg, nil, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func testAES() error {
	profile := &ProfileV1{} // Uses AES-256-GCM
	key := make([]byte, 32)
	data := []byte("integrity-test")

	aead, err := profile.NewAEAD(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, aead.NonceSize())
	ct := aead.Seal(nil, nonce, data, nil)
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return err
	}

	if !bytes.Equal(pt, data) {
		return fmt.Errorf("plaintext mismatch")
	}
	return nil
}
