package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Constants for algorithm selection in dynamic profiles
const (
	AlgoXChaCha20Poly1305 = byte(0)
	AlgoAES256GCM         = byte(1)

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

func (p *DynamicProfile) ID() byte { return p.CustomID }

func (p *DynamicProfile) SaltSize() int { return p.CustomSalt }

func (p *DynamicProfile) NonceSize() int { return p.CustomNonc }

func (p *DynamicProfile) DeriveKey(passphrase, salt []byte) []byte {
	switch p.KdfType {
	case KdfArgon2id:
		return argon2.IDKey(passphrase, salt, p.ArgonTime, p.ArgonMem, p.ArgonThrd, 32)
	default:
		return nil
	}
}

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
	default:
		return nil, fmt.Errorf("unsupported cipher type: %d", p.CipherType)
	}
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
