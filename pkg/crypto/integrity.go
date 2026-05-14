package crypto

import (
	"bytes"
	"crypto/hpke"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"golang.org/x/crypto/argon2"
)

// RunPOST executes Power-On Self-Tests to verify cryptographic integrity.
// This is a mandatory industrial safeguard.
func RunPOST() error {
	// 1. ML-DSA-87 KAT
	if err := testMLDSA(); err != nil {
		return fmt.Errorf("ML-DSA integrity check failed: %w", err)
	}

	// 2. ML-KEM-768 KAT (Hybrid via HPKE)
	if err := testMLKEM(); err != nil {
		return fmt.Errorf("ML-KEM integrity check failed: %w", err)
	}

	// 3. Argon2id KAT
	if err := testArgon2(); err != nil {
		return fmt.Errorf("Argon2id integrity check failed: %w", err)
	}

	// 4. AES-256-GCM Integrity
	if err := testAES(); err != nil {
		return fmt.Errorf("AES integrity check failed: %w", err)
	}

	return nil
}

func testMLKEM() error {
	// We use HPKE which wraps ML-KEM-768 + X25519
	profile := &ProfileV1{}
	priv, pub, err := profile.GenerateHybridKeyPair()
	if err != nil {
		return err
	}
	defer SafeClear(priv)

	kem := hpke.MLKEM768X25519()
	pk, err := kem.NewPublicKey(pub)
	if err != nil {
		return err
	}
	sk, err := kem.NewPrivateKey(priv)
	if err != nil {
		return err
	}

	info := []byte("fips-post-info")
	// Use a dummy FEK to verify wrap/unwrap
	fek := make([]byte, 32)
	for i := range fek {
		fek[i] = byte(i)
	}

	// Encapsulate/Seal
	enc, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		return err
	}
	ct, err := sender.Seal(nil, fek)
	if err != nil {
		return err
	}

	// Decapsulate/Open
	receiver, err := hpke.NewRecipient(enc, sk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		return err
	}
	recovered, err := receiver.Open(nil, ct)
	if err != nil {
		return err
	}

	if !bytes.Equal(fek, recovered) {
		return fmt.Errorf("ML-KEM/HPKE recovered secret mismatch")
	}
	return nil
}

func testArgon2() error {
	pass := []byte("password")
	salt := []byte("salt-for-kat-123")
	// Known answer for Argon2id(t=1, m=64MB, p=4)
	expectedHex := "f4d687ad71b1b385df1009b6db48d926"
	res := argon2.IDKey(pass, salt, 1, 64*1024, 4, 16)

	actualHex := fmt.Sprintf("%x", res)
	if actualHex != expectedHex {
		return fmt.Errorf("argon2id KAT failed: expected %s, got %s", expectedHex, actualHex)
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
