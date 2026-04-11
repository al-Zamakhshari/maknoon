package crypto

import (
	"crypto/cipher"
	"fmt"
	"sync"
)

// CryptoProfile defines the cryptographic primitives and parameters for a Maknoon version.
type CryptoProfile interface {
	ID() byte

	// KDF & Symmetric Encryption
	SaltSize() int
	NonceSize() int
	DeriveKey(passphrase, salt []byte) []byte
	NewAEAD(key []byte) (cipher.AEAD, error)

	// Asymmetric KEM (Key Encapsulation Mechanism)
	KEMName() string
	GenerateKEMKeyPair() (pub, priv []byte, err error)
	KEMEncapsulate(pubKey []byte) (ct, ss []byte, err error)
	KEMDecapsulate(privKey, ct []byte) (ss []byte, err error)
	KEMCiphertextSize() int

	// Digital Signatures
	SIGName() string
	GenerateSIGKeyPair() (pub, priv []byte, err error)
	Sign(data, privKey []byte) ([]byte, error)
	Verify(data, sig, pubKey []byte) bool
}

var (
	profiles = make(map[byte]CryptoProfile)
	mu       sync.RWMutex
)

// RegisterProfile adds a new cryptographic profile to the registry.
func RegisterProfile(p CryptoProfile) {
	mu.Lock()
	defer mu.Unlock()
	profiles[p.ID()] = p
}

// GetProfile retrieves a cryptographic profile by its ID.
func GetProfile(id byte) (CryptoProfile, error) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := profiles[id]
	if !ok {
		return nil, fmt.Errorf("unsupported cryptographic profile ID: %d", id)
	}
	return p, nil
}

// DefaultProfile returns the standard NIST PQC profile (v1).
func DefaultProfile() CryptoProfile {
	p, _ := GetProfile(1)
	return p
}
