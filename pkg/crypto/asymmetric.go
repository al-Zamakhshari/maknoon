// Package crypto provides the core cryptographic primitives and streaming
// encryption logic for Maknoon.
package crypto

import (
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// GeneratePQKeyPair generates a fresh Hybrid KEM and SIG (ML-DSA-87 + Ed25519) keypair.
func GeneratePQKeyPair(profileID byte) (kemPub, kemPriv, sigPub, sigPriv []byte, err error) {
	profile, err := GetProfile(profileID, nil)
	if err != nil {
		profile = DefaultProfile()
	}

	kemPriv, kemPub, err = profile.GenerateHybridKeyPair()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	mldsaPub, mldsaPriv, err := profile.GenerateSIGKeyPair()
	if err != nil {
		SafeClear(kemPriv)
		return nil, nil, nil, nil, err
	}

	// Generate Ed25519 for libp2p and BEP-44 compatibility (appended to ML-DSA bundle).
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		SafeClear(kemPriv)
		SafeClear(mldsaPriv)
		return nil, nil, nil, nil, err
	}

	sigPub = append(mldsaPub, edPub...)
	sigPriv = append(mldsaPriv, edPriv...)

	return
}

// DeriveSIGPublic derives the public key from an ML-DSA+Ed25519 hybrid private key.
func DeriveSIGPublic(privKeyBytes []byte, profileID byte) ([]byte, error) {
	profile, err := GetProfile(profileID, nil)
	if err != nil {
		profile = DefaultProfile()
	}

	// ML-DSA part
	mldsaSize := 0
	if p, ok := profile.(*ProfileV1); ok {
		mldsaSize = mldsa87.PrivateKeySize
		_ = p
	} else {
		// Fallback or handle other profiles
		mldsaSize = mldsa87.PrivateKeySize
	}

	if len(privKeyBytes) < mldsaSize {
		return nil, fmt.Errorf("invalid SIG private key size")
	}

	mldsaPriv := privKeyBytes[:mldsaSize]
	mldsaPub, err := profile.DeriveSIGPublic(mldsaPriv)
	if err != nil {
		return nil, err
	}

	// Ed25519 part
	if len(privKeyBytes) >= mldsaSize+ed25519.PrivateKeySize {
		edPriv := ed25519.PrivateKey(privKeyBytes[mldsaSize : mldsaSize+ed25519.PrivateKeySize])
		edPub := edPriv.Public().(ed25519.PublicKey)
		return append(mldsaPub, edPub...), nil
	}

	return mldsaPub, nil
}

// DeriveKEMPublic derives the public key from a Hybrid KEM private key.
func DeriveKEMPublic(privKeyBytes []byte) ([]byte, error) {
	kem := hpke.MLKEM768X25519()
	sk, err := kem.NewPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid KEM private key: %w", err)
	}
	return sk.PublicKey().Bytes(), nil
}

// SignData signs a message using a Post-Quantum private key.
func SignData(message []byte, privKeyBytes []byte) ([]byte, error) {
	return DefaultProfile().Sign(message, privKeyBytes)
}

// VerifySignature verifies a Post-Quantum signature against a message and public key.
func VerifySignature(message []byte, signature []byte, pubKeyBytes []byte) bool {
	return DefaultProfile().Verify(message, signature, pubKeyBytes)
}

// DerivePublicKey derives a public key from a private key using the specified profile.
func DerivePublicKey(privKey []byte, profileID byte) []byte {
	profile, err := GetProfile(profileID, nil)
	if err != nil {
		profile = DefaultProfile()
	}
	pk, _ := profile.DeriveKEMPublic(privKey)
	return pk
}
