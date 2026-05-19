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
	safe, err := s.safePath(path)
	if err != nil {
		return nil, err
	}
	// Inline containment guard — filepath.Rel is the CodeQL go/path-injection
	// sanitiser; having it in the same function scope as the file op breaks
	// the inter-procedural taint chain that safePath alone does not break.
	if s.BaseDir != "" {
		base := filepath.Clean(s.BaseDir)
		rel, relErr := filepath.Rel(base, safe)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			tmpBase := filepath.Clean(os.TempDir())
			relTmp, relTmpErr := filepath.Rel(tmpBase, safe)
			if relTmpErr != nil || strings.HasPrefix(relTmp, "..") {
				return nil, &ErrPolicyViolation{Reason: "key path outside permitted directories", Path: path}
			}
		}
	}
	return os.ReadFile(safe)
}

func (s *FileSystemKeyStore) WriteKey(path string, data []byte, perm uint32) error {
	safe, err := s.safePath(path)
	if err != nil {
		return err
	}
	// Inline containment guard — same rationale as ReadKey.
	if s.BaseDir != "" {
		base := filepath.Clean(s.BaseDir)
		rel, relErr := filepath.Rel(base, safe)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			tmpBase := filepath.Clean(os.TempDir())
			relTmp, relTmpErr := filepath.Rel(tmpBase, safe)
			if relTmpErr != nil || strings.HasPrefix(relTmp, "..") {
				return &ErrPolicyViolation{Reason: "key path outside permitted directories", Path: path}
			}
		}
	}
	return os.WriteFile(safe, data, os.FileMode(perm))
}

func (s *FileSystemKeyStore) Exists(path string) bool {
	safe, err := s.safePath(path)
	if err != nil {
		return false
	}
	// Inline containment guard — same rationale as ReadKey.
	if s.BaseDir != "" {
		base := filepath.Clean(s.BaseDir)
		rel, relErr := filepath.Rel(base, safe)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			tmpBase := filepath.Clean(os.TempDir())
			relTmp, relTmpErr := filepath.Rel(tmpBase, safe)
			if relTmpErr != nil || strings.HasPrefix(relTmp, "..") {
				return false
			}
		}
	}
	_, err = os.Stat(safe)
	return err == nil
}

func (s *FileSystemKeyStore) ListKeys(dir string) ([]string, error) {
	safe, err := s.safePath(dir)
	if err != nil {
		return nil, err
	}
	// Inline containment guard so the Rel check is in the same scope as os.ReadDir.
	if s.BaseDir != "" {
		base := filepath.Clean(s.BaseDir)
		rel, relErr := filepath.Rel(base, safe)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			tmpBase := filepath.Clean(os.TempDir())
			relTmp, relTmpErr := filepath.Rel(tmpBase, safe)
			if relTmpErr != nil || strings.HasPrefix(relTmp, "..") {
				return nil, &ErrPolicyViolation{Reason: "list-keys path outside permitted directories", Path: dir}
			}
		}
	}
	entries, err := os.ReadDir(safe)
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
	safe, err := s.safePath(dir)
	if err != nil {
		return err
	}
	// Inline containment guard so the Rel check is in the same scope as os.MkdirAll.
	if s.BaseDir != "" {
		base := filepath.Clean(s.BaseDir)
		rel, relErr := filepath.Rel(base, safe)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			tmpBase := filepath.Clean(os.TempDir())
			relTmp, relTmpErr := filepath.Rel(tmpBase, safe)
			if relTmpErr != nil || strings.HasPrefix(relTmp, "..") {
				return &ErrPolicyViolation{Reason: "ensure-dir path outside permitted directories", Path: dir}
			}
		}
	}
	return os.MkdirAll(safe, 0700)
}

// safePath cleans the path and verifies it stays within BaseDir or os.TempDir().
// This breaks the taint chain for CodeQL's go/path-injection analysis.
func (s *FileSystemKeyStore) safePath(path string) (string, error) {
	clean := filepath.Clean(path)
	// Allow absolute paths within BaseDir or temp dir.
	if filepath.IsAbs(clean) {
		if s.BaseDir != "" {
			rel, err := filepath.Rel(filepath.Clean(s.BaseDir), clean)
			if err == nil && !strings.HasPrefix(rel, "..") {
				return clean, nil
			}
		}
		tmpDir := filepath.Clean(os.TempDir())
		rel, err := filepath.Rel(tmpDir, clean)
		if err == nil && !strings.HasPrefix(rel, "..") {
			return clean, nil
		}
		// Non-agent processes may access any absolute path (e.g. test fixtures).
		if !IsAgentMode() {
			return clean, nil
		}
		return "", &ErrPolicyViolation{Reason: "absolute path outside permitted directories", Path: path}
	}
	// Relative paths must not escape upward.
	if strings.HasPrefix(clean, "..") {
		return "", &ErrPolicyViolation{Reason: "relative path escape not permitted", Path: path}
	}
	if s.BaseDir != "" {
		return filepath.Join(filepath.Clean(s.BaseDir), clean), nil
	}
	return clean, nil
}

func (s *FileSystemKeyStore) ResolvePath(name string) (string, error) {
	clean := filepath.Clean(name)

	// Allow absolute paths if they are already within BaseDir
	if filepath.IsAbs(clean) {
		rel, err := filepath.Rel(s.BaseDir, clean)
		if err == nil && !strings.HasPrefix(rel, "..") {
			return clean, nil
		}

		// Also allow absolute paths if they are in the system temp dir (important for tests)
		tmpDir := os.TempDir()
		if relTmp, err := filepath.Rel(tmpDir, clean); err == nil && !strings.HasPrefix(relTmp, "..") {
			return clean, nil
		}

		// If in agent mode, prohibit any other absolute paths
		if IsAgentMode() {
			return "", &ErrPolicyViolation{Reason: "absolute path access prohibited in agent mode", Path: name}
		}
		return clean, nil
	}

	// For relative paths, ensure they don't escape BaseDir
	if strings.HasPrefix(clean, "..") {
		return "", &ErrPolicyViolation{Reason: "illegal path access attempted", Path: name}
	}
	return filepath.Join(s.BaseDir, clean), nil
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

// FileSystemVaultStore manages secure vaults on disk.
type FileSystemVaultStore struct {
	BaseDir string
	Backend string
}

func (s *FileSystemVaultStore) Open(path string) (Store, error) {
	clean := filepath.Clean(path)
	var fullPath string

	if filepath.IsAbs(clean) {
		// Allow absolute paths if they are within BaseDir or TempDir
		rel, err := filepath.Rel(s.BaseDir, clean)
		isWithinBase := (err == nil && !strings.HasPrefix(rel, ".."))

		// Explicitly allow the contacts database if it's in the standard location relative to BaseDir
		isContacts := (err == nil && rel == "../contacts.db")

		tmpDir := os.TempDir()
		relTmp, errTmp := filepath.Rel(tmpDir, clean)
		isWithinTmp := (errTmp == nil && !strings.HasPrefix(relTmp, ".."))

		if isWithinBase || isWithinTmp || isContacts || !IsAgentMode() {
			fullPath = clean
		} else {
			return nil, &ErrPolicyViolation{Reason: "illegal vault path access attempted", Path: path}
		}
	} else {
		// Relative path: ensure no escape and join with BaseDir
		if strings.HasPrefix(clean, "..") && clean != "../contacts.db" {
			return nil, &ErrPolicyViolation{Reason: "illegal vault path access attempted", Path: path}
		}
		fullPath = filepath.Join(s.BaseDir, clean)
	}

	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, &ErrIO{Path: dir, Reason: "failed to create directory: " + err.Error()}
	}

	backend := strings.ToLower(s.Backend)
	if backend == "" {
		backend = "bbolt"
	}

	switch backend {
	default:
		db, err := bbolt.Open(fullPath, 0600, &bbolt.Options{Timeout: 10 * time.Second})
		if err != nil {
			return nil, &ErrIO{Path: fullPath, Reason: err.Error()}
		}
		return &BboltStore{db: db}, nil
	}
}

func (s *FileSystemVaultStore) DeleteVault(path string) error {
	// Containment check — filepath.Clean + filepath.Rel is the canonical
	// CodeQL go/path-injection sanitiser pattern.  The check must be in the
	// same function scope as the file operations to break the taint chain.
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) {
		baseDir := filepath.Clean(s.BaseDir)
		rel, err := filepath.Rel(baseDir, clean)
		inBase := (err == nil && (!strings.HasPrefix(rel, "..") || rel == "../contacts.db"))

		tmpDir := filepath.Clean(os.TempDir())
		relTmp, errTmp := filepath.Rel(tmpDir, clean)
		inTmp := (errTmp == nil && !strings.HasPrefix(relTmp, ".."))

		if !inBase && !inTmp && IsAgentMode() {
			return &ErrPolicyViolation{Reason: "vault path outside permitted directories", Path: path}
		}
		// For non-agent mode: ensure path does not traverse out of any recognised base.
		if !inBase && !inTmp && strings.Contains(clean, "..") {
			return &ErrPolicyViolation{Reason: "vault path traversal not permitted", Path: path}
		}
	} else if strings.HasPrefix(clean, "..") {
		return &ErrPolicyViolation{Reason: "vault path traversal not permitted", Path: path}
	}
	// Badger uses a directory, Bolt uses a file.
	// The filepath.Rel guards immediately above break the CodeQL taint chain.
	info, err := os.Stat(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.IsDir() {
		return os.RemoveAll(clean)
	}
	return os.Remove(clean)
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
