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

	// Name returns the human-readable name of the profile.
	Name() string

	// KEMName returns the name of the Key Encapsulation Mechanism.
	KEMName() string

	// KEM methods
	// GenerateHybridKeyPair generates a new hybrid key pair.
	GenerateHybridKeyPair() (priv, pub []byte, err error)
	// DeriveKEMPublic derives the public key from a private key.
	DeriveKEMPublic(priv []byte) ([]byte, error)
	// RecipientBlockSize returns the total size of an encrypted FEK block for one recipient.
	RecipientBlockSize() int
	// WrapFEK encapsulates an ephemeral symmetric key (FEK) for a recipient.
	WrapFEK(recipientPub []byte, flags byte, fekEnclave *memguard.Enclave) ([]byte, error)
	// UnwrapFEK decapsulates the FEK from the header material.
	UnwrapFEK(recipientPriv []byte, flags byte, headerData []byte) (*memguard.Enclave, error)

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

	// 1. Try to load from Global Config (where custom named profiles are stored)
	_ = GetGlobalConfig() // This triggers LoadConfig which registers profiles
	mu.RLock()
	p, ok = profiles[id]
	mu.RUnlock()
	if ok {
		return p, nil
	}

	// 2. Automatic Discovery for Secret Profiles (3-127) in legacy separate files
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

// DefaultProfile returns the cryptographic profile specified in the configuration.
func DefaultProfile() Profile {
	id := GetGlobalConfig().Performance.DefaultProfile
	if id == 0 {
		id = 1
	}
	p, _ := GetProfile(id, nil)
	return p
}

func (e *Engine) LoadCustomProfile(ectx *EngineContext, path string) (*DynamicProfile, error) {
	return LoadCustomProfile(path)
}

func (e *Engine) GenerateRandomProfile(ectx *EngineContext, id byte) *DynamicProfile {
	return GenerateRandomProfile(id)
}

func (e *Engine) ValidateProfile(ectx *EngineContext, p *DynamicProfile) error {
	return p.Validate()
}

// SafeClearString clears a string slice by setting each element to empty.
func SafeClearString(s []string) {
	for i := range s {
		s[i] = ""
	}
}
