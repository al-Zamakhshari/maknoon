package crypto

import (
	"crypto/cipher"
	"fmt"
	"io"
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
// If ID >= 128 and not registered, it reads the next 7 bytes from r to unpack a dynamic profile.
func GetProfile(id byte, r io.Reader) (CryptoProfile, error) {
	mu.RLock()
	p, ok := profiles[id]
	mu.RUnlock()
	if ok {
		return p, nil
	}

	if id >= 128 {
		if r == nil {
			return nil, fmt.Errorf("reader required for unknown dynamic profile ID: %d", id)
		}
		packed := make([]byte, 7)
		if _, err := io.ReadFull(r, packed); err != nil {
			return nil, fmt.Errorf("failed to read packed profile: %w", err)
		}
		return UnpackDynamicProfile(id, packed)
	}

	return nil, fmt.Errorf("unsupported cryptographic profile ID: %d", id)
}

// DefaultProfile returns the standard NIST PQC profile (v1).
func DefaultProfile() CryptoProfile {
	p, _ := GetProfile(1, nil)
	return p
}
