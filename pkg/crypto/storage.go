package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

// KeyStore defines the interface for persisting and retrieving cryptographic keys.
type KeyStore interface {
	ReadKey(path string) ([]byte, error)
	WriteKey(path string, data []byte, perm uint32) error
	Exists(path string) bool
	ListKeys(dir string) ([]string, error)
	EnsureDir(dir string) error
	ResolvePath(name string) (string, error)
	GetBaseDir() string
}

// ConfigStore defines the interface for managing engine configuration.
type ConfigStore interface {
	Load() (*Config, error)
	Save(conf *Config) error
}

// Store defines the interface for a generic transactional key-value store.
// This allows Maknoon to be backend-agnostic (e.g., bbolt, SQL, or remote).
type Store interface {
	Update(fn func(tx Transaction) error) error
	View(fn func(tx Transaction) error) error
	Close() error
}

// Transaction defines operations allowed within a store transaction.
type Transaction interface {
	Get(bucket, key string) []byte
	Put(bucket, key string, val []byte) error
	Delete(bucket, key string) error
	ForEach(bucket string, fn func(k, v []byte) error) error
	CreateBucket(bucket string) error
}

// VaultStore defines the high-level interface for managing multiple vaults.
type VaultStore interface {
	Open(path string) (Store, error)
	DeleteVault(path string) error
	ListVaults() ([]string, error)
}

// FileSystemKeyStore is the default implementation that uses the local disk.
type FileSystemKeyStore struct {
	BaseDir string
}

func (s *FileSystemKeyStore) ReadKey(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (s *FileSystemKeyStore) WriteKey(path string, data []byte, perm uint32) error {
	return os.WriteFile(path, data, os.FileMode(perm))
}

func (s *FileSystemKeyStore) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (s *FileSystemKeyStore) ListKeys(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	var keys []string
	for _, e := range entries {
		keys = append(keys, e.Name())
	}
	return keys, nil
}

func (s *FileSystemKeyStore) EnsureDir(dir string) error {
	return os.MkdirAll(dir, 0700)
}

func (s *FileSystemKeyStore) ResolvePath(name string) (string, error) {
	if filepath.IsAbs(name) || strings.Contains(name, string(os.PathSeparator)) {
		return name, nil
	}
	return filepath.Join(s.BaseDir, name), nil
}

func (s *FileSystemKeyStore) GetBaseDir() string {
	return s.BaseDir
}

// FileSystemConfigStore manages engine configuration on disk.
type FileSystemConfigStore struct {
	Path string
}

func (s *FileSystemConfigStore) Load() (*Config, error) {
	return LoadConfig()
}

func (s *FileSystemConfigStore) Save(conf *Config) error {
	return conf.Save()
}

// FileSystemVaultStore manages secure vaults on disk using bbolt.
type FileSystemVaultStore struct {
	BaseDir string
}

func (s *FileSystemVaultStore) Open(path string) (Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, &ErrIO{Path: dir, Reason: "failed to create directory: " + err.Error()}
	}

	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, &ErrIO{Path: path, Reason: err.Error()}
	}
	return &BboltStore{db: db}, nil
}

func (s *FileSystemVaultStore) DeleteVault(path string) error {
	return os.Remove(path)
}

func (s *FileSystemVaultStore) ListVaults() ([]string, error) {
	entries, err := os.ReadDir(s.BaseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	var vaults []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".vault") {
			vaults = append(vaults, e.Name())
		}
	}
	return vaults, nil
}

// BboltStore implements the Store interface using bbolt.
type BboltStore struct {
	db *bbolt.DB
}

func (s *BboltStore) Update(fn func(tx Transaction) error) error {
	return s.db.Update(func(btx *bbolt.Tx) error {
		return fn(&BboltTransaction{tx: btx})
	})
}

func (s *BboltStore) View(fn func(tx Transaction) error) error {
	return s.db.View(func(btx *bbolt.Tx) error {
		return fn(&BboltTransaction{tx: btx})
	})
}

func (s *BboltStore) Close() error {
	return s.db.Close()
}

// BboltTransaction implements the Transaction interface using bbolt.
type BboltTransaction struct {
	tx *bbolt.Tx
}

func (t *BboltTransaction) Get(bucket, key string) []byte {
	b := t.tx.Bucket([]byte(bucket))
	if b == nil {
		return nil
	}
	return b.Get([]byte(key))
}

func (t *BboltTransaction) Put(bucket, key string, val []byte) error {
	b, err := t.tx.CreateBucketIfNotExists([]byte(bucket))
	if err != nil {
		return err
	}
	return b.Put([]byte(key), val)
}

func (t *BboltTransaction) Delete(bucket, key string) error {
	b := t.tx.Bucket([]byte(bucket))
	if b == nil {
		return nil
	}
	return b.Delete([]byte(key))
}

func (t *BboltTransaction) ForEach(bucket string, fn func(k, v []byte) error) error {
	b := t.tx.Bucket([]byte(bucket))
	if b == nil {
		return nil
	}
	return b.ForEach(fn)
}

func (t *BboltTransaction) CreateBucket(bucket string) error {
	_, err := t.tx.CreateBucketIfNotExists([]byte(bucket))
	return err
}
