package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
)

const (
	vaultBucket = "secrets"
	metaBucket  = "metadata"
	saltKey     = "salt"
)

// VaultEntry represents a single secret stored in the vault.
type VaultEntry struct {
	Service  string      `json:"service"`
	Username string      `json:"username"`
	Password SecretBytes `json:"password"`
	URL      string      `json:"url,omitempty"`
	Note     string      `json:"note,omitempty"` // Legacy compatibility
}

// SealEntry binary encodes and encrypts a vault entry.
func SealEntry(entry *VaultEntry, key []byte) ([]byte, error) {
	b, _ := json.Marshal(entry)
	profile := DefaultProfile()
	aead, err := profile.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, b, nil)
	return append(nonce, ciphertext...), nil
}

// OpenEntry decrypts and parses a vault entry.
func OpenEntry(payload, key []byte) (*VaultEntry, error) {
	profile := DefaultProfile()
	aead, err := profile.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	if len(payload) < nonceSize {
		return nil, &ErrFormat{Reason: "invalid vault entry format"}
	}

	nonce := payload[:nonceSize]
	ciphertext := payload[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, &ErrAuthentication{Reason: "failed to decrypt vault entry"}
	}

	var entry VaultEntry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		return nil, &ErrFormat{Reason: "failed to parse vault entry"}
	}
	return &entry, nil
}

// DeriveVaultKey uses the default profile's KDF to derive a vault master key.
func DeriveVaultKey(passphrase, salt []byte) []byte {
	return DefaultProfile().DeriveKey(passphrase, salt)
}

// SplitVault shards the vault master key using Shamir's Secret Sharing.
func SplitVault(vaultPath string, threshold, shares int, passphrase string) ([]string, error) {
	shards, err := SplitSecret([]byte(passphrase), threshold, shares)
	if err != nil {
		return nil, err
	}

	var results []string
	for _, s := range shards {
		results = append(results, s.ToMnemonic())
	}
	return results, nil
}

// RecoverVault combines shards to recover the master passphrase.
func RecoverVault(mnemonics []string, vaultPath, output, passphrase string) (string, error) {
	var shards []Share
	for _, m := range mnemonics {
		s, err := FromMnemonic(m)
		if err != nil {
			return "", err
		}
		shards = append(shards, *s)
	}

	combined, err := CombineShares(shards)
	if err != nil {
		return "", err
	}
	return string(combined), nil
}

func Sha256Hex(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
