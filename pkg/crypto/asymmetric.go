// Package crypto provides the core cryptographic primitives and streaming
// encryption logic for Maknoon.
package crypto

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// GeneratePQKeyPair generates a Post-Quantum Kyber1024 keypair for encryption and an MLDSA-87 keypair for signing.
func GeneratePQKeyPair() (kemPub, kemPriv, sigPub, sigPriv []byte, err error) {
	// 1. KEM (Encryption)
	pk, sk, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	kemPub, _ = pk.MarshalBinary()
	kemPriv, _ = sk.MarshalBinary()

	// 2. SIG (Signing)
	spk, ssk, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		// Zero out KEM keys before failing
		for i := range kemPriv {
			kemPriv[i] = 0
		}
		return nil, nil, nil, nil, err
	}
	sigPub, _ = spk.MarshalBinary()
	sigPriv, _ = ssk.MarshalBinary()

	return kemPub, kemPriv, sigPub, sigPriv, nil
}

// SignData signs a message using an ML-DSA-87 private key.
func SignData(message []byte, privKeyBytes []byte) ([]byte, error) {
	// Zero out the input bytes after unmarshaling to protect memory
	defer func() {
		for i := range privKeyBytes {
			privKeyBytes[i] = 0
		}
	}()

	sk := new(mldsa87.PrivateKey)
	if err := sk.UnmarshalBinary(privKeyBytes); err != nil {
		return nil, fmt.Errorf("invalid signing key: %w", err)
	}

	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(sk, message, nil, true, sig); err != nil {
		return nil, fmt.Errorf("signing failure: %w", err)
	}
	return sig, nil
}

// VerifySignature verifies an ML-DSA-87 signature.
func VerifySignature(message []byte, signature []byte, pubKeyBytes []byte) bool {
	pk := new(mldsa87.PublicKey)
	if err := pk.UnmarshalBinary(pubKeyBytes); err != nil {
		return false
	}
	return mldsa87.Verify(pk, message, nil, signature)
}
