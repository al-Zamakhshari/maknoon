package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.etcd.io/bbolt"
)

const (
	vaultBucket = "secrets"
	metaBucket  = "metadata"
	saltKey     = "salt"
)

// VaultSet encrypts and saves a vault entry to disk.
func (e *Engine) VaultSet(vaultPath string, entry *VaultEntry, passphrase []byte, pin string) error {
	if vaultPath == "" {
		vaultPath = filepath.Join(e.Config.Paths.VaultsDir, "default.vault")
	}

	if err := e.Policy.ValidatePath(vaultPath); err != nil {
		return err
	}

	return SetVaultEntry(vaultPath, entry, passphrase)
}

// VaultGet reads and decrypts a vault entry from disk.
func (e *Engine) VaultGet(vaultPath string, service string, passphrase []byte, pin string) (*VaultEntry, error) {
	if vaultPath == "" {
		vaultPath = filepath.Join(e.Config.Paths.VaultsDir, "default.vault")
	}

	if err := e.Policy.ValidatePath(vaultPath); err != nil {
		return nil, err
	}

	return GetVaultEntry(vaultPath, service, passphrase)
}

func (e *Engine) VaultDelete(name string) error {
	path, err := e.resolveVaultPath(name)
	if err != nil {
		return err
	}
	if err := e.Policy.ValidatePath(path); err != nil {
		return err
	}
	return SecureDelete(path)
}

func (e *Engine) VaultRename(oldName, newName string) error {
	oldPath, err := e.resolveVaultPath(oldName)
	if err != nil {
		return err
	}
	newPath, err := e.resolveVaultPath(newName)
	if err != nil {
		return err
	}

	if err := e.Policy.ValidatePath(oldPath); err != nil {
		return err
	}
	if err := e.Policy.ValidatePath(newPath); err != nil {
		return err
	}

	if _, err := os.Stat(oldPath); err != nil {
		return fmt.Errorf("vault '%s' not found", oldName)
	}
	if _, err := os.Stat(newPath); err == nil {
		return fmt.Errorf("target vault '%s' already exists", newName)
	}

	return os.Rename(oldPath, newPath)
}

func (e *Engine) resolveVaultPath(name string) (string, error) {
	if strings.Contains(name, string(os.PathSeparator)) {
		return name, nil
	}
	return filepath.Join(e.Config.Paths.VaultsDir, name+".db"), nil
}

// GetVaultEntry reads a single encrypted entry from a bbolt database.
func GetVaultEntry(path string, service string, passphrase []byte) (*VaultEntry, error) {
	if len(passphrase) == 0 {
		return nil, &ErrAuthentication{Reason: "vault master passphrase required"}
	}

	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var ciphertext []byte
	var salt []byte
	err = db.View(func(tx *bbolt.Tx) error {
		meta := tx.Bucket([]byte(metaBucket))
		if meta != nil {
			salt = meta.Get([]byte(saltKey))
		}
		b := tx.Bucket([]byte(vaultBucket))
		if b == nil {
			return nil
		}
		h := sha256.Sum256([]byte(strings.ToLower(service)))
		ciphertext = b.Get([]byte(hex.EncodeToString(h[:])))
		return nil
	})
	if err != nil {
		return nil, err
	}

	if salt == nil {
		return nil, &ErrState{Reason: "vault is uninitialized (missing salt)"}
	}

	masterKey := DeriveVaultKey(passphrase, salt)
	defer SafeClear(masterKey)

	if ciphertext == nil {
		return nil, fmt.Errorf("service not found")
	}

	return OpenEntry(ciphertext, masterKey)
}

// SetVaultEntry encrypts and saves a single entry to a bbolt database.
func SetVaultEntry(path string, entry *VaultEntry, passphrase []byte) error {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Update(func(tx *bbolt.Tx) error {
		meta, _ := tx.CreateBucketIfNotExists([]byte(metaBucket))
		salt := meta.Get([]byte(saltKey))
		if salt == nil {
			salt = make([]byte, 32)
			if _, err := rand.Read(salt); err != nil {
				return err
			}
			meta.Put([]byte(saltKey), salt)
		}

		masterKey := DeriveVaultKey(passphrase, salt)
		defer SafeClear(masterKey)

		ciphertext, err := SealEntry(entry, masterKey)
		if err != nil {
			return err
		}

		b, _ := tx.CreateBucketIfNotExists([]byte(vaultBucket))
		h := sha256.Sum256([]byte(strings.ToLower(entry.Service)))
		return b.Put([]byte(hex.EncodeToString(h[:])), ciphertext)
	})
}

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
