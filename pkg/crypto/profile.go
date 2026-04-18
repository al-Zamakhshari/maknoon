// Package crypto implements the core cryptographic pipeline for Maknoon.
package crypto

import (
	"crypto/cipher"
	"crypto/hpke"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/awnumar/memguard"
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

	// V2 Hybrid HPKE methods
	// GenerateHybridKeyPair generates a new hybrid key pair (ML-KEM-768 + X25519).
	GenerateHybridKeyPair() (hpke.PrivateKey, hpke.PublicKey, error)
	// WrapFEK encapsulates an ephemeral symmetric key (FEK) for a recipient.
	WrapFEK(recipientPub hpke.PublicKey, flags byte, fekEnclave *memguard.Enclave) ([]byte, error)
	// UnwrapFEK decapsulates the FEK from the header material.
	UnwrapFEK(recipientPriv hpke.PrivateKey, flags byte, headerData []byte) (*memguard.Enclave, error)

	// SIGName returns the name of the digital signature algorithm.
	SIGName() string
	// SIGSize returns the size of the signature in bytes.
	SIGSize() int
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

	// Unpack from reader if ID >= 128 (Portable)
	if id >= 128 && r != nil {
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
		RegisterProfile(dp)
		return dp, nil
	}

	return nil, fmt.Errorf("unsupported or unregistered cryptographic profile ID: %d", id)
}

// DefaultProfile returns the standard NIST PQC profile (v1).
func DefaultProfile() Profile {
	p, _ := GetProfile(1, nil)
	return p
}

// SafeClear deterministically zeroizes a standard Go byte slice.
func SafeClear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SafeClearString clears a string slice by setting each element to empty.
func SafeClearString(s []string) {
	for i := range s {
		s[i] = ""
	}
}
