package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"golang.org/x/crypto/argon2"
)

// Constants for algorithm selection in dynamic profiles.
const (
	AlgoAES256GCM = byte(1)

	KdfArgon2id = byte(0)
)

// DynamicProfile is a profile defined at runtime either from a file or from header bytes.
// It inherits V2 Hybrid HPKE (X25519 + ML-KEM-768) and ML-DSA-87 signatures from ProfileV1.
type DynamicProfile struct {
	ProfileV1 `json:"-"`

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

// Name returns the profile name.
func (p *DynamicProfile) Name() string {
	if p.CustomID >= 128 {
		return "portable"
	}
	return "dynamic"
}

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
	if p.CipherType != AlgoAES256GCM {
		return nil, fmt.Errorf("unsupported cipher type: %d (only 1:AES-256-GCM supported)", p.CipherType)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Validate checks if the profile uses supported algorithms and sensible security parameters.
func (p *DynamicProfile) Validate() error {
	if p.CipherType != AlgoAES256GCM {
		return fmt.Errorf("unsupported cipher type: %d (only 1:AES-256-GCM supported)", p.CipherType)
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
	if p.CustomNonc != 12 {
		return fmt.Errorf("AES-GCM families require exactly 12-byte nonce (got %d)", p.CustomNonc)
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
	// 1. Cipher type — AES-256-GCM is the only supported option.
	cipherType := AlgoAES256GCM

	// 2. AES-GCM families require 12-byte nonce
	nonceSize := 12

	// 3. Random Salt Size (16 to 64 bytes)
	s, _ := rand.Int(rand.Reader, big.NewInt(49))
	saltSize := 16 + int(s.Uint64())

	// 4. Random Argon2 Settings
	maxTime := uint32(10)
	maxMem := uint32(1024 * 1024) // 1GB
	maxThrd := uint8(8)

	it, _ := rand.Int(rand.Reader, big.NewInt(int64(maxTime)))
	iterations := uint32(it.Uint64()) + 1
	mem, _ := rand.Int(rand.Reader, big.NewInt(int64(maxMem-1024)))
	memory := uint32(mem.Uint64()) + 1024
	th, _ := rand.Int(rand.Reader, big.NewInt(int64(maxThrd-1)))
	threads := uint8(th.Uint64()) + 1

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

// LoadCustomProfile reads a custom profile from a JSON file, validates it, and registers it.
// This function remains for internal usage but Engine now provides a context-aware wrapper.
func LoadCustomProfile(path string) (*DynamicProfile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var dp DynamicProfile
	if err := json.Unmarshal(raw, &dp); err != nil {
		return nil, err
	}
	if err := dp.Validate(); err != nil {
		return nil, err
	}
	RegisterProfile(&dp)
	return &dp, nil
}
