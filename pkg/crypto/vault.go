package crypto

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// DeriveVaultKey derives a 32-byte master key from a password and salt using Argon2id.
func DeriveVaultKey(password, salt []byte) []byte {
	key := argon2.IDKey(password, salt, 3, 64*1024, 4, 32)
	return key
}

// VaultEntry represents a single secret stored in the vault.
type VaultEntry struct {
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
	Note     string `json:"note"`
}

// SealEntry encrypts a VaultEntry into a ciphertext blob using the master key.
func SealEntry(entry *VaultEntry, masterKey []byte) ([]byte, error) {
	// Zero out master key on exit to protect memory
	defer func() {
		for i := range masterKey {
			masterKey[i] = 0
		}
	}()

	plaintext, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// OpenEntry decrypts a ciphertext blob into a VaultEntry.
func OpenEntry(ciphertext []byte, masterKey []byte) (*VaultEntry, error) {
	// Zero out master key on exit to protect memory
	defer func() {
		for i := range masterKey {
			masterKey[i] = 0
		}
	}()

	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	nonce := ciphertext[:aead.NonceSize()]
	actualCiphertext := ciphertext[aead.NonceSize():]

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
