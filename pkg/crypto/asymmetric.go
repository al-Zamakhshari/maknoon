// Package crypto provides the core cryptographic primitives and streaming
// encryption logic for Maknoon.
package crypto

import (
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/crypto/hkdf"
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

// DeriveNostrKeypair derives a secp256k1 private key (32 raw bytes) from the
// ML-DSA-87+Ed25519 SIG private key using HKDF-SHA256. The key is used only
// as a Nostr transport signing key; it is never stored on disk.
func DeriveNostrKeypair(sigPriv []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, sigPriv, []byte("maknoon-nostr-transport-v1"), []byte("secp256k1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}
	return key, nil
}

// nostrPrivKeyToHexPub returns the secp256k1 x-only public key hex (Nostr format)
// for the given 32-byte raw private key.
func nostrPrivKeyToHexPub(privBytes []byte) (string, error) {
	privHex := fmt.Sprintf("%x", privBytes)
	pubHex, err := nostr.GetPublicKey(privHex)
	if err != nil {
		return "", fmt.Errorf("failed to derive nostr public key: %w", err)
	}
	return pubHex, nil
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
