package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/argon2"
)

func init() {
	RegisterProfile(&ProfileV2{
		ProfileV1: ProfileV1{
			ArgonTime: 3,
			ArgonMem:  64 * 1024,
			ArgonThrd: 4,
		},
	})
}

// ProfileV2 implements a "High-Compatibility" suite using AES-256-GCM.
// It inherits the new V2 Hybrid HPKE (X25519 + ML-KEM-768) from ProfileV1.
type ProfileV2 struct {
	ProfileV1
}

// ID returns the profile identifier (2).
func (p *ProfileV2) ID() byte { return 2 }

// SaltSize returns the salt size in bytes (32).
func (p *ProfileV2) SaltSize() int { return 32 }

// NonceSize returns the standard AES-GCM nonce size (12 bytes).
func (p *ProfileV2) NonceSize() int { return 12 }

// DeriveKey derives a symmetric key using Argon2id.
func (p *ProfileV2) DeriveKey(passphrase, salt []byte) []byte {
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
