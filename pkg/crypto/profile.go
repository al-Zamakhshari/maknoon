// Package crypto implements the core cryptographic pipeline for Maknoon.
package crypto

import (
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Profile defines the cryptographic primitives and parameters for a Maknoon version.
type Profile interface {
	// ID returns the unique identifier for this profile.
	ID() byte

	// SaltSize returns the size of the salt in bytes.
	SaltSize() int
	// NonceSize returns the size of the nonce in bytes.
	NonceSize() int
	// DeriveKey derives a symmetric key from a passphrase and salt.
	DeriveKey(passphrase, salt []byte) []byte
	// NewAEAD creates a new AEAD instance for symmetric encryption.
	NewAEAD(key []byte) (cipher.AEAD, error)

	// KEMName returns the name of the Key Encapsulation Mechanism.
	KEMName() string
	// GenerateKEMKeyPair generates a new KEM key pair.
	GenerateKEMKeyPair() (pub, priv []byte, err error)
	// KEMEncapsulate generates a shared secret and its encapsulation for a public key.
	KEMEncapsulate(pubKey []byte) (ct, ss []byte, err error)
	// KEMDecapsulate recovers a shared secret from its encapsulation using a private key.
	KEMDecapsulate(privKey, ct []byte) (ss []byte, err error)
	// KEMCiphertextSize returns the size of the KEM ciphertext in bytes.
	KEMCiphertextSize() int

	// SIGName returns the name of the digital signature algorithm.
	SIGName() string
	// GenerateSIGKeyPair generates a new digital signature key pair.
	GenerateSIGKeyPair() (pub, priv []byte, err error)
	// Sign signs the data using a private key.
	Sign(data, privKey []byte) ([]byte, error)
	// Verify verifies the signature for the data using a public key.
	Verify(data, sig, pubKey []byte) bool
}

var (
	profiles = make(map[byte]Profile)
	mu       sync.RWMutex
)

// RegisterProfile adds a new cryptographic profile to the registry.
func RegisterProfile(p Profile) {
	mu.Lock()
	defer mu.Unlock()
	profiles[p.ID()] = p
}

// GetProfile retrieves a cryptographic profile by its ID.
// 1. Checks memory registry.
// 2. If ID < 128, attempts to auto-load from ~/.maknoon/profiles/ID.json.
// 3. If ID >= 128, reads 7 packed bytes from r to unpack a dynamic profile.
func GetProfile(id byte, r io.Reader) (Profile, error) {
	mu.RLock()
	p, ok := profiles[id]
	mu.RUnlock()
	if ok {
		return p, nil
	}

	// Automatic Discovery for Secret Profiles (3-127)
	if id > 2 && id < 128 {
		home, err := os.UserHomeDir()
		if err == nil {
			profilePath := filepath.Join(home, MaknoonDir, ProfilesDir, fmt.Sprintf("%d.json", id))
			if _, err := os.Stat(profilePath); err == nil {
				raw, err := os.ReadFile(profilePath)
				if err == nil {
					var dp DynamicProfile
					if err := json.Unmarshal(raw, &dp); err == nil {
						if err := dp.Validate(); err == nil {
							RegisterProfile(&dp)
							return &dp, nil
						}
					}
				}
			}
		}
	}

	if id >= 128 {
		if r == nil {
			return nil, fmt.Errorf("reader required for unknown dynamic profile ID: %d", id)
		}
		packed := make([]byte, 7)
		if _, err := io.ReadFull(r, packed); err != nil {
			return nil, fmt.Errorf("failed to read packed profile: %w", err)
		}
		dp, err := UnpackDynamicProfile(id, packed)
		if err != nil {
			return nil, err
		}
		if err := dp.Validate(); err != nil {
			return nil, fmt.Errorf("embedded profile validation failed: %w", err)
		}
		return dp, nil
	}

	return nil, fmt.Errorf("unsupported cryptographic profile ID: %d", id)
}

// DefaultProfile returns the standard NIST PQC profile (v1).
func DefaultProfile() Profile {
	p, _ := GetProfile(1, nil)
	return p
}
