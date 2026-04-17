package crypto

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
)

// DeriveVaultKey derives a 32-byte master key from a password and salt using the default profile.
func DeriveVaultKey(password, salt []byte) []byte {
	return DefaultProfile().DeriveKey(password, salt)
}

// VaultEntry represents a single secret stored in the vault.
type VaultEntry struct {
	Service  string `json:"service"`
	Username string `json:"username"`
	Password []byte `json:"password"`
	Note     string `json:"note"`
}

// SealEntry encrypts a VaultEntry into a ciphertext blob using the master key and the default profile.
func SealEntry(entry *VaultEntry, masterKey []byte) ([]byte, error) {
	plaintext, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}

	profile := DefaultProfile()
	aead, err := profile.NewAEAD(masterKey)
	if err != nil {
		return nil, err
	}

	nonceSize := profile.NonceSize()
	// Header (1 byte for ProfileID) | Nonce | Ciphertext
	result := make([]byte, 1+nonceSize+len(plaintext)+aead.Overhead())
	result[0] = profile.ID()
	nonce := result[1 : 1+nonceSize]

	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("entropy failure: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	copy(result[1+nonceSize:], ciphertext)

	return result, nil
}

// OpenEntry decrypts a ciphertext blob into a VaultEntry.
func OpenEntry(data []byte, masterKey []byte) (*VaultEntry, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	profile, err := GetProfile(data[0], nil)
	if err != nil {
		return nil, err
	}

	aead, err := profile.NewAEAD(masterKey)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(data) < 1+nonceSize {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	nonce := data[1 : 1+nonceSize]
	actualCiphertext := data[1+nonceSize:]

	plaintext, err := aead.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: invalid master key")
	}

	var entry VaultEntry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		return nil, err
	}

	// Memory Hygiene: Zero out the plaintext buffer
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()

	return &entry, nil
}
