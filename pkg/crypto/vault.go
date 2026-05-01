package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

const (
	vaultBucket = "secrets"
	metaBucket  = "metadata"
	saltKey     = "salt"
)

// VaultSet encrypts and saves a vault entry to disk.
func (e *Engine) VaultSet(ectx *EngineContext, vaultPath string, entry *VaultEntry, passphrase []byte, pin string, overwrite bool) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultWrite); err != nil {
		return err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := e.resolveVaultPath(vaultPath)
	if err != nil {
		return err
	}

	if err := ectx.Policy.ValidatePath(path); err != nil {
		return err
	}

	return SetVaultEntry(path, entry, passphrase, overwrite)
}

// VaultGet reads and decrypts a vault entry from disk.
func (e *Engine) VaultGet(ectx *EngineContext, vaultPath string, service string, passphrase []byte, pin string) (*VaultEntry, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultRead); err != nil {
		return nil, err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := e.resolveVaultPath(vaultPath)
	if err != nil {
		return nil, err
	}

	if err := ectx.Policy.ValidatePath(path); err != nil {
		return nil, err
	}

	return GetVaultEntry(path, service, passphrase)
}

func (e *Engine) VaultDelete(ectx *EngineContext, name string) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultDelete); err != nil {
		return err
	}
	path, err := e.resolveVaultPath(name)
	if err != nil {
		return err
	}
	if err := ectx.Policy.ValidatePath(path); err != nil {
		return err
	}

	return e.Vaults.DeleteVault(path)
}

func (e *Engine) VaultRename(ectx *EngineContext, oldName, newName string) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultWrite); err != nil {
		return err
	}
	oldPath, err := e.resolveVaultPath(oldName)
	if err != nil {
		return err
	}
	newPath, err := e.resolveVaultPath(newName)
	if err != nil {
		return err
	}

	if err := ectx.Policy.ValidatePath(oldPath); err != nil {
		return err
	}
	if err := ectx.Policy.ValidatePath(newPath); err != nil {
		return err
	}

	if _, err := os.Stat(oldPath); err != nil {
		return &ErrState{Reason: fmt.Sprintf("vault '%s' not found", oldName)}
	}
	if _, err := os.Stat(newPath); err == nil {
		return &ErrState{Reason: fmt.Sprintf("target vault '%s' already exists", newName)}
	}

	return os.Rename(oldPath, newPath)
}

func (e *Engine) VaultList(ectx *EngineContext, vaultPath string, passphrase []byte) ([]VaultListEntry, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultRead); err != nil {
		return nil, err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := e.resolveVaultPath(vaultPath)
	if err != nil {
		return nil, err
	}
	if err := ectx.Policy.ValidatePath(path); err != nil {
		return nil, err
	}
	return ListVaultEntries(path, passphrase)
}

func (e *Engine) VaultSplit(ectx *EngineContext, vaultPath string, threshold, shares int, passphrase string) ([]string, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultRead); err != nil {
		return nil, err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := e.resolveVaultPath(vaultPath)
	if err != nil {
		return nil, err
	}
	return SplitVault(path, threshold, shares, passphrase)
}

func (e *Engine) VaultRecover(ectx *EngineContext, mnemonics []string, vaultPath string, output string, passphrase string) (string, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultWrite); err != nil {
		return "", err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := e.resolveVaultPath(vaultPath)
	if err != nil {
		return "", err
	}
	return RecoverVault(mnemonics, path, output, passphrase)
}

func (e *Engine) resolveVaultPath(name string) (string, error) {
	if name == "" {
		return "", &ErrFormat{Reason: "vault name required"}
	}
	if filepath.IsAbs(name) || strings.Contains(name, string(os.PathSeparator)) {
		return name, nil
	}
	return filepath.Join(e.Config.Paths.VaultsDir, name+".vault"), nil
}

// VaultEntry represents a single secret stored in the vault.
type VaultEntry struct {
	Service  string      `json:"service"`
	Username string      `json:"username"`
	Password SecretBytes `json:"password"`
	URL      string      `json:"url,omitempty"`
	Note     string      `json:"note,omitempty"` // Legacy compatibility
}

// SetVaultEntry is the package-level helper that performs the actual bbolt operation.
func SetVaultEntry(vaultPath string, entry *VaultEntry, passphrase []byte, overwrite bool) error {
	db, err := bbolt.Open(vaultPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return &ErrIO{Path: vaultPath, Reason: err.Error()}
	}
	defer db.Close()

	return db.Update(func(tx *bbolt.Tx) error {
		// Get or create salt
		meta, _ := tx.CreateBucketIfNotExists([]byte(metaBucket))
		salt := meta.Get([]byte(saltKey))
		if salt == nil {
			salt = make([]byte, 16)
			if _, err := io.ReadFull(rand.Reader, salt); err != nil {
				return err
			}
			if err := meta.Put([]byte(saltKey), salt); err != nil {
				return err
			}
		}

		key := DeriveVaultKey(passphrase, salt)
		defer SafeClear(key)

		payload, err := SealEntry(entry, key)
		if err != nil {
			return err
		}

		secrets, _ := tx.CreateBucketIfNotExists([]byte(vaultBucket))

		// Use Hashed key for privacy
		serviceKey := Sha256Hex([]byte(strings.ToLower(entry.Service)))
		if !overwrite {
			if secrets.Get([]byte(serviceKey)) != nil {
				return &ErrState{Reason: fmt.Sprintf("service '%s' already exists (use overwrite to replace)", entry.Service)}
			}
		}

		return secrets.Put([]byte(serviceKey), payload)
	})
}

// GetVaultEntry is the package-level helper that performs the actual bbolt operation.
func GetVaultEntry(vaultPath, service string, passphrase []byte) (*VaultEntry, error) {
	db, err := bbolt.Open(vaultPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, &ErrIO{Path: vaultPath, Reason: err.Error()}
	}
	defer db.Close()

	var entry *VaultEntry
	err = db.View(func(tx *bbolt.Tx) error {
		meta := tx.Bucket([]byte(metaBucket))
		if meta == nil {
			return &ErrAuthentication{Reason: "vault is uninitialized"}
		}
		salt := meta.Get([]byte(saltKey))
		if salt == nil {
			return &ErrAuthentication{Reason: "vault salt missing"}
		}

		secrets := tx.Bucket([]byte(vaultBucket))
		if secrets == nil {
			return &ErrState{Reason: "vault is empty"}
		}

		// Use Hashed key
		serviceKey := Sha256Hex([]byte(strings.ToLower(service)))
		payload := secrets.Get([]byte(serviceKey))
		if payload == nil {
			return &ErrState{Reason: fmt.Sprintf("service '%s' not found", service)}
		}

		key := DeriveVaultKey(passphrase, salt)
		defer SafeClear(key)

		var err error
		entry, err = OpenEntry(payload, key)
		return err
	})

	return entry, err
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

// ListVaultEntries returns all service names and usernames in a vault.
func ListVaultEntries(vaultPath string, passphrase []byte) ([]VaultListEntry, error) {
	db, err := bbolt.Open(vaultPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, &ErrIO{Path: vaultPath, Reason: err.Error()}
	}
	defer db.Close()

	var entries []VaultListEntry
	err = db.View(func(tx *bbolt.Tx) error {
		meta := tx.Bucket([]byte(metaBucket))
		if meta == nil {
			return &ErrAuthentication{Reason: "vault is uninitialized"}
		}
		salt := meta.Get([]byte(saltKey))
		if salt == nil {
			return &ErrAuthentication{Reason: "vault salt missing"}
		}

		key := DeriveVaultKey(passphrase, salt)
		defer SafeClear(key)

		secrets := tx.Bucket([]byte(vaultBucket))
		if secrets == nil {
			return nil
		}

		return secrets.ForEach(func(_, v []byte) error {
			entry, err := OpenEntry(v, key)
			if err == nil {
				entries = append(entries, VaultListEntry{
					Service:  entry.Service,
					Username: entry.Username,
				})
			}
			return nil
		})
	})
	return entries, err
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
