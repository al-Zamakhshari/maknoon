package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/argon2"
)

func init() {
	RegisterProfile(&ProfileV2{})
}

// ProfileV2 implements a "High-Compatibility" suite using AES-256-GCM and a faster KDF.
// Note: This is mainly to demonstrate cryptographic agility.
type ProfileV2 struct {
	ProfileV1 // Inherit KEM/SIG from V1 for now
}

// ID returns the profile identifier (2).
func (p *ProfileV2) ID() byte { return 2 }

// SaltSize returns the salt size in bytes (32).
func (p *ProfileV2) SaltSize() int { return 32 }

// NonceSize returns the standard AES-GCM nonce size (12 bytes).
func (p *ProfileV2) NonceSize() int { return 12 }

// DeriveKey derives a symmetric key using Argon2id.
func (p *ProfileV2) DeriveKey(passphrase, salt []byte) []byte {
	// Standard high-security Argon2 settings (matching Profile 1)
	return argon2.IDKey(passphrase, salt, 3, 64*1024, 4, 32)
}

// NewAEAD returns a new AES-GCM AEAD.
func (p *ProfileV2) NewAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// GenerateKEMKeyPair generates a new KEM keypair (inherited from V1).
func (p *ProfileV2) GenerateKEMKeyPair() (pub, priv []byte, err error) {
	// For V2, we'll keep using the same KEM as V1 for identity compatibility
	return p.ProfileV1.GenerateKEMKeyPair()
}
