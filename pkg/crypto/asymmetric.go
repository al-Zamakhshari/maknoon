// Package crypto provides the core cryptographic primitives and streaming
// encryption logic for Maknoon.
package crypto

import (
	"crypto/hpke"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/nbd-wtf/go-nostr"
)

// GeneratePQKeyPair generates a fresh Hybrid (ML-KEM + X25519), ML-DSA, and Secp256k1 (Nostr) keypair.
func GeneratePQKeyPair() (kemPub, kemPriv, sigPub, sigPriv, nostrPub, nostrPriv []byte, err error) {
	profile := DefaultProfile()

	priv, pub, err := profile.GenerateHybridKeyPair()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	kemPriv, err = priv.Bytes()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	kemPub = pub.Bytes()

	sigPub, sigPriv, err = profile.GenerateSIGKeyPair()
	if err != nil {
		SafeClear(kemPriv)
		return nil, nil, nil, nil, nil, nil, err
	}

	// Generate Secp256k1 for Nostr
	nostrPrivStr := nostr.GeneratePrivateKey()
	nostrPubStr, err := nostr.GetPublicKey(nostrPrivStr)
	if err != nil {
		SafeClear(kemPriv)
		SafeClear(sigPriv)
		return nil, nil, nil, nil, nil, nil, err
	}
	nostrPriv = []byte(nostrPrivStr)
	nostrPub = []byte(nostrPubStr)

	return
}

// DeriveNostrPublic derives the hex public key from a Nostr private key hex string.
func DeriveNostrPublic(privKeyBytes []byte) ([]byte, error) {
	pub, err := nostr.GetPublicKey(string(privKeyBytes))
	if err != nil {
		return nil, err
	}
	return []byte(pub), nil
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

// DeriveSIGPublic derives the public key from an ML-DSA private key.
func DeriveSIGPublic(privKeyBytes []byte) ([]byte, error) {
	sk := new(mldsa87.PrivateKey)
	if err := sk.UnmarshalBinary(privKeyBytes); err != nil {
		return nil, fmt.Errorf("invalid SIG private key: %w", err)
	}
	pk := sk.Public().(*mldsa87.PublicKey)
	return pk.MarshalBinary()
}

// SignData signs a message using a Post-Quantum private key.
func SignData(message []byte, privKeyBytes []byte) ([]byte, error) {
	return DefaultProfile().Sign(message, privKeyBytes)
}

// VerifySignature verifies a Post-Quantum signature against a message and public key.
func VerifySignature(message []byte, signature []byte, pubKeyBytes []byte) bool {
	return DefaultProfile().Verify(message, signature, pubKeyBytes)
}
