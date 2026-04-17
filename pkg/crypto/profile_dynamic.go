package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/secure-io/siv-go"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Constants for algorithm selection in dynamic profiles.
const (
	AlgoXChaCha20Poly1305 = byte(0)
	AlgoAES256GCM         = byte(1)
	AlgoAES256GCMSIV      = byte(2)

	KdfArgon2id = byte(0)
)

// DynamicProfile is a profile defined at runtime either from a file or from header bytes.
type DynamicProfile struct {
	ProfileV1 `json:"-"` // Default KEM/SIG behavior for now

	CustomID   byte   `json:"id"`
	CipherType byte   `json:"cipher"`
	KdfType    byte   `json:"kdf"`
	ArgonTime  uint32 `json:"kdf_iterations"`
	ArgonMem   uint32 `json:"kdf_memory"`
	ArgonThrd  uint8  `json:"kdf_threads"`
	CustomSalt int    `json:"salt_size"`
	CustomNonc int    `json:"nonce_size"`
}

// ID returns the custom profile identifier.
func (p *DynamicProfile) ID() byte { return p.CustomID }

// SaltSize returns the custom salt size in bytes.
func (p *DynamicProfile) SaltSize() int { return p.CustomSalt }

// NonceSize returns the custom nonce size in bytes.
func (p *DynamicProfile) NonceSize() int { return p.CustomNonc }

// DeriveKey derives a symmetric key using the configured KDF.
func (p *DynamicProfile) DeriveKey(passphrase, salt []byte) []byte {
	switch p.KdfType {
	case KdfArgon2id:
		return argon2.IDKey(passphrase, salt, p.ArgonTime, p.ArgonMem, p.ArgonThrd, 32)
	default:
		return nil
	}
}

// NewAEAD returns a new AEAD instance based on the configured cipher type.
func (p *DynamicProfile) NewAEAD(key []byte) (cipher.AEAD, error) {
	switch p.CipherType {
	case AlgoXChaCha20Poly1305:
		return chacha20poly1305.NewX(key)
	case AlgoAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case AlgoAES256GCMSIV:
		return siv.NewGCM(key)
	default:
		return nil, fmt.Errorf("unsupported cipher type: %d (only 0:XChaCha20, 1:AES-GCM, 2:AES-GCM-SIV supported)", p.CipherType)
	}
}

// Validate checks if the profile uses supported algorithms and sensible security parameters.
func (p *DynamicProfile) Validate() error {
	if p.CipherType > 2 {
		return fmt.Errorf("unsupported cipher type: %d", p.CipherType)
	}
	if p.KdfType != KdfArgon2id {
		return fmt.Errorf("unsupported KDF type: %d", p.KdfType)
	}
	if p.ArgonTime < 1 {
		return fmt.Errorf("invalid KDF iterations: %d (min 1)", p.ArgonTime)
	}
	if p.ArgonMem < 1024 {
		return fmt.Errorf("invalid KDF memory: %d KB (min 1024)", p.ArgonMem)
	}
	if p.CustomSalt < 8 {
		return fmt.Errorf("invalid salt size: %d (min 8)", p.CustomSalt)
	}
	// Check nonce size compatibility
	if (p.CipherType == AlgoAES256GCM || p.CipherType == AlgoAES256GCMSIV) && p.CustomNonc != 12 {
		return fmt.Errorf("AES-GCM families require exactly 12-byte nonce (got %d)", p.CustomNonc)
	}
	if p.CipherType == AlgoXChaCha20Poly1305 && p.CustomNonc != 24 {
		return fmt.Errorf("XChaCha20-Poly1305 requires exactly 24-byte nonce (got %d)", p.CustomNonc)
	}
	return nil
}

// Pack serializes the dynamic profile into 7 bytes for "Self-Contained" headers.
func (p *DynamicProfile) Pack() []byte {
	res := make([]byte, 7)
	res[0] = p.CipherType
	res[1] = p.KdfType
	res[2] = byte(p.ArgonTime)
	res[3] = byte(p.ArgonMem / 1024) // Store in MB
	res[4] = p.ArgonThrd
	res[5] = byte(p.CustomSalt)
	res[6] = byte(p.CustomNonc)
	return res
}

// UnpackDynamicProfile creates a DynamicProfile from packed bytes.
func UnpackDynamicProfile(id byte, b []byte) (*DynamicProfile, error) {
	if len(b) < 7 {
		return nil, fmt.Errorf("invalid packed profile data")
	}
	return &DynamicProfile{
		CustomID:   id,
		CipherType: b[0],
		KdfType:    b[1],
		ArgonTime:  uint32(b[2]),
		ArgonMem:   uint32(b[3]) * 1024,
		ArgonThrd:  b[4],
		CustomSalt: int(b[5]),
		CustomNonc: int(b[6]),
	}, nil
}

// GenerateRandomProfile creates a technically sound and secure profile with random parameters.
func GenerateRandomProfile(id byte) *DynamicProfile {
	// 1. Random Cipher (0, 1, or 2)
	c, _ := rand.Int(rand.Reader, big.NewInt(3))
	cipherType := byte(c.Uint64())

	// 2. Determine Nonce Size based on Cipher
	nonceSize := 24
	if cipherType == AlgoAES256GCM || cipherType == AlgoAES256GCMSIV {
		nonceSize = 12
	}

	// 3. Random Salt Size (16 to 64 bytes)
	s, _ := rand.Int(rand.Reader, big.NewInt(49))
	saltSize := 16 + int(s.Uint64())

	// 4. Random Argon2 Settings (Realistic but varying)
	// Iterations: 1 to 10
	it, _ := rand.Int(rand.Reader, big.NewInt(10))
	iterations := uint32(1 + it.Uint64())

	// Memory: 16MB to 512MB (in KB steps of 16MB)
	memSteps, _ := rand.Int(rand.Reader, big.NewInt(32))
	memory := uint32(16384 + (memSteps.Uint64() * 16384))

	// Threads: 1 to 8
	th, _ := rand.Int(rand.Reader, big.NewInt(8))
	threads := uint8(1 + th.Uint64())

	return &DynamicProfile{
		CustomID:   id,
		CipherType: cipherType,
		KdfType:    KdfArgon2id,
		ArgonTime:  iterations,
		ArgonMem:   memory,
		ArgonThrd:  threads,
		CustomSalt: saltSize,
		CustomNonc: nonceSize,
	}
}
