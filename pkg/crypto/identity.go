package crypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	// MaknoonDir is the default directory name for Maknoon data.
	MaknoonDir = ".maknoon"
	// KeysDir is the subdirectory for storing keys.
	KeysDir = "keys"
	// VaultsDir is the subdirectory for storing vaults.
	VaultsDir = "vaults"
	// ProfilesDir is the subdirectory for custom profiles.
	ProfilesDir = "profiles"
)

// IsAgentMode returns true if the application is running in non-interactive agent mode.
func IsAgentMode() bool {
	return viper.GetString("agent_mode") == "1"
}

// Identity represents a full PQC keypair (KEM + SIG).
type Identity struct {
	Name    string
	KEMPub  []byte
	KEMPriv SecretBytes
	SIGPub  []byte
	SIGPriv SecretBytes
}

// IdentityManager handles local key storage and resolution.
type IdentityManager struct {
	Store    KeyStore
	Contacts *ContactManager
	P2P      MultiaddrsProvider
	Config   *Config
}

// NewIdentityManager creates an IdentityManager with default paths.
func NewIdentityManager() *IdentityManager {
	home := GetUserHomeDir()
	return &IdentityManager{
		Store: &FileSystemKeyStore{
			BaseDir: filepath.Join(home, MaknoonDir, KeysDir),
		},
	}
}

// NewCustomIdentityManager allows injecting a specific storage backend.
func NewCustomIdentityManager(store KeyStore, contacts *ContactManager) *IdentityManager {
	return &IdentityManager{
		Store:    store,
		Contacts: contacts,
	}
}

// ResolveKeyPath checks if a key exists locally, in ~/.maknoon/keys/, or in environment variables.
//
// Deprecated: use IdentityManager.ResolveKeyPath or Engine.ResolveKeyPath instead.
// This package-level helper is retained only for external callers that have not yet
// migrated; new code should use the manager method which goes through the managed store.
func ResolveKeyPath(path string, envVar string) string {
	m := NewIdentityManager()
	return m.ResolveKeyPath(path, envVar)
}

// ResolveKeyPath is a convenience method on IdentityManager.
func (m *IdentityManager) ResolveKeyPath(path, envVar string) string {
	if path != "" {
		if m.Store.Exists(path) {
			return path
		}
		// Check manager's KeysDir via ResolvePath
		managedPath, err := m.Store.ResolvePath(path)
		if err == nil && m.Store.Exists(managedPath) {
			return managedPath
		}
	}
	if envVar != "" {
		if env := os.Getenv(envVar); env != "" {
			if _, err := os.Stat(env); err == nil {
				return env
			}
		}
	}
	return ""
}

// SaveIdentity persists an identity's keys to disk, optionally encrypted.
func (m *IdentityManager) SaveIdentity(basePath, baseName string, kemPub, kemPriv, sigPub, sigPriv, passphrase []byte, profileID byte) error {
	writeKey := func(path string, data []byte, isPrivate bool) error {
		if len(data) == 0 {
			return nil
		}
		finalData := data
		if isPrivate && len(passphrase) > 0 {
			var b bytes.Buffer
			if err := EncryptStreamV2(bytes.NewReader(data), &b, passphrase, 0, nil, 1, profileID, nil); err != nil {
				return err
			}
			finalData = b.Bytes()
		}
		mode := uint32(0644)
		if isPrivate {
			mode = 0600
		}
		return m.Store.WriteKey(path, finalData, mode)
	}

	if err := writeKey(basePath+".kem.key", kemPriv, true); err != nil {
		return err
	}
	if err := writeKey(basePath+".kem.pub", kemPub, false); err != nil {
		return err
	}
	if err := writeKey(basePath+".sig.key", sigPriv, true); err != nil {
		return err
	}
	if err := writeKey(basePath+".sig.pub", sigPub, false); err != nil {
		return err
	}
	return nil
}

// CreateIdentity generates and saves a new Post-Quantum identity.
func (m *IdentityManager) CreateIdentity(name string, passphrase []byte, pin string, isStdin bool, profile string) (*IdentityResult, error) {
	profileID := byte(1)
	switch profile {
	case "", "nist", "pq":
		profileID = 1
	case "conservative", "legacy":
		profileID = 3
	case "aes":
		return nil, fmt.Errorf("profile 'aes' (ID 2) is not a registered built-in; use 'nist' (ID 1) or 'conservative' (ID 3)")
	default:
		// Allow numeric custom profile IDs passed through from the CLI resolver.
		var customID int
		if _, err := fmt.Sscanf(profile, "%d", &customID); err == nil && customID > 0 && customID < 256 {
			profileID = byte(customID)
		} else {
			return nil, fmt.Errorf("unknown profile %q; valid built-ins: nist (1), conservative (3)", profile)
		}
	}

	if err := EnsureMaknoonDirs(); err != nil {
		return nil, err
	}

	kemPub, kemPriv, sigPub, sigPriv, err := GeneratePQKeyPair(profileID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypairs: %w", err)
	}

	defer func() {
		SafeClear(kemPriv)
		SafeClear(sigPriv)
	}()

	basePath, baseName, err := m.ResolveBaseKeyPath(name)
	if err != nil {
		return nil, err
	}

	if err := m.SaveIdentity(basePath, baseName, kemPub, kemPriv, sigPub, sigPriv, passphrase, profileID); err != nil {
		return nil, err
	}

	return &IdentityResult{
		Status:   "success",
		BasePath: basePath,
		BaseName: baseName,
	}, nil
}

func (m *IdentityManager) ResolveBaseKeyPath(name string) (string, string, error) {
	if name == "" {
		return "", "", &ErrState{Reason: "identity name required"}
	}

	// 1. Resolve via Store
	base, err := m.Store.ResolvePath(name)
	if err != nil {
		return "", "", err
	}

	// Clean suffixes if provided in name
	base = strings.TrimSuffix(base, ".kem.key")
	base = strings.TrimSuffix(base, ".sig.key")
	base = strings.TrimSuffix(base, ".key")

	return base, filepath.Base(base), nil
}

// LoadIdentity handles the full flow of resolving and unlocking an identity.
func (m *IdentityManager) LoadIdentity(name string, passphrase []byte, pin string, isStdin bool) (*Identity, error) {
	if name == "" {
		name = GetGlobalConfig().DefaultIdentity
	}
	if name == "" {
		name = "default"
	}
	basePath, _, err := m.ResolveBaseKeyPath(name)

	if err != nil {
		return nil, err
	}

	id := &Identity{Name: name}

	// Load Public Keys
	id.KEMPub, _ = m.Store.ReadKey(basePath + ".kem.pub")
	id.SIGPub, _ = m.Store.ReadKey(basePath + ".sig.pub")
	// Load and Unlock KEM Private Key
	id.KEMPriv, err = m.LoadPrivateKey(basePath+".kem.key", passphrase, pin, isStdin)
	if err != nil {
		return nil, err
	}

	// Load and Unlock SIG Private Key
	id.SIGPriv, err = m.LoadPrivateKey(basePath+".sig.key", passphrase, pin, isStdin)
	if err != nil {
		return nil, err
	}

	return id, nil
}

// LoadPrivateKey handles the decryption of a protected key file.
func (m *IdentityManager) LoadPrivateKey(path string, passphrase []byte, pin string, isStdin bool) ([]byte, error) {
	if !m.Store.Exists(path) {
		return nil, &ErrIO{Path: path, Reason: "key file not found"}
	}

	// Case 1: Backward-compat path for keys enrolled with FIDO2 hardware tokens
	// (--fido2 CLI flag removed in v1.3; this path handles existing .fido2 keys).
	fidoPath := path + ".fido2"
	if m.Store.Exists(fidoPath) {
		return m.UnlockPrivateKeyWithFIDOOrPass(passphrase, pin, path, isStdin)
	}

	// Case 2: Check if key is plain-text or protected
	data, err := m.Store.ReadKey(path)
	if err != nil {
		return nil, &ErrIO{Path: path, Reason: err.Error()}
	}

	// Detect an encrypted key by its magic bytes — V1 (MAKN) or V2 (MAK2).
	if len(data) >= 4 && (string(data[:4]) == MagicHeader || string(data[:4]) == MagicHeaderV2Sym) {
		var decrypted bytes.Buffer
		_, _, err = DecryptStream(bytes.NewReader(data), &decrypted, passphrase, 1, false)
		if err != nil {
			return nil, &ErrAuthentication{Reason: fmt.Sprintf("failed to unlock key: %v", err)}
		}
		return decrypted.Bytes(), nil
	}

	// Plain-text key (no password used during generation)
	return data, nil
}

func (m *IdentityManager) UnlockPrivateKeyWithFIDOOrPass(password []byte, _ string, resolvedPath string, _ bool) ([]byte, error) {
	data, err := m.Store.ReadKey(resolvedPath)
	if err != nil {
		return nil, &ErrIO{Path: resolvedPath, Reason: err.Error()}
	}

	var decrypted bytes.Buffer
	if _, _, err := DecryptStream(bytes.NewReader(data), &decrypted, password, 1, false); err != nil {
		return nil, &ErrAuthentication{Reason: "passphrase incorrect or key file corrupt"}
	}
	return decrypted.Bytes(), nil
}

// ResolvePublicKey takes a petname (@handle), a local path, or raw hex and returns the KEM public key.
// ResolveIdentityInfo resolves a handle or file path and returns the full IdentityRecord.
// For @handle recipients the record includes SIGPubKey, ExpiresAt, and the handle.
// For file-path recipients only KEMPubKey is populated (no expiry or fingerprint).
func (m *IdentityManager) ResolveIdentityInfo(input string, tofu bool) (*IdentityRecord, error) {
	if strings.HasPrefix(input, "@") {
		if m.Contacts != nil {
			if c, err := m.Contacts.Get(input); err == nil {
				return &IdentityRecord{
					Handle:    input,
					KEMPubKey: c.KEMPubKey,
					SIGPubKey: c.SIGPubKey,
				}, nil
			}
		}
		reg := NewIdentityRegistry(nil)
		record, err := reg.Resolve(context.Background(), input)
		if err != nil {
			return nil, fmt.Errorf("identity not found: %w", err)
		}
		if tofu && m.Contacts != nil {
			_ = m.Contacts.Add(&Contact{
				Petname:   input,
				KEMPubKey: record.KEMPubKey,
				SIGPubKey: record.SIGPubKey,
				AddedAt:   time.Now(),
				Notes:     "Automatically added via discovery (TOFU)",
			})
		}
		return record, nil
	}
	// Local file path — return KEMPubKey only.
	kemPub, err := m.ResolvePublicKey(input, tofu)
	if err != nil {
		return nil, err
	}
	return &IdentityRecord{KEMPubKey: kemPub}, nil
}

func (m *IdentityManager) ResolvePublicKey(input string, tofu bool) ([]byte, error) {
	// 1. Handle Petnames (@handle)
	if strings.HasPrefix(input, "@") {
		// Check local contacts first (skip if contacts not initialized).
		if m.Contacts != nil {
			if c, err := m.Contacts.Get(input); err == nil {
				return c.KEMPubKey, nil
			}
		}
		// 2. DHT/DNS/Nostr Discovery
		reg := NewIdentityRegistry(nil)
		record, err := reg.Resolve(context.Background(), input)
		if err != nil {
			return nil, fmt.Errorf("identity not found: %w", err)
		}
		if tofu && m.Contacts != nil {
			_ = m.Contacts.Add(&Contact{
				Petname:   input,
				KEMPubKey: record.KEMPubKey,
				SIGPubKey: record.SIGPubKey,
				AddedAt:   time.Now(),
				Notes:     "Automatically added via discovery (TOFU)",
			})
		}
		return record.KEMPubKey, nil
	}

	// 3. Handle Local Paths or Managed Keys
	cleanInput := filepath.Clean(input)
	if IsAgentMode() && filepath.IsAbs(cleanInput) {
		// Allow absolute paths if they are in the system temp dir
		tmpDir := os.TempDir()
		relTmp, errTmp := filepath.Rel(tmpDir, cleanInput)
		isWithinTmp := (errTmp == nil && !strings.HasPrefix(relTmp, ".."))
		if !isWithinTmp {
			return nil, &ErrPolicyViolation{Reason: "absolute path access prohibited in agent mode", Path: input}
		}
	} else if IsAgentMode() && strings.HasPrefix(cleanInput, "..") {
		return nil, &ErrPolicyViolation{Reason: "relative path escape prohibited in agent mode", Path: input}
	}

	resolvedPath := cleanInput
	if _, err := os.Stat(cleanInput); err != nil {
		// Not a direct local path, check the managed store
		if managed, err := m.Store.ResolvePath(input); err == nil {
			resolvedPath = filepath.Clean(managed)
		}
	}

	if _, err := os.Stat(resolvedPath); err == nil {
		return os.ReadFile(resolvedPath)
	}

	// 4. Handle Raw Hex
	b, err := hex.DecodeString(input)
	if err == nil && (len(b) == 1184 || len(b) == 32) { // Kyber1024 or similar
		return b, nil
	}

	return nil, fmt.Errorf("unable to resolve public key from: %s", input)
}

func (m *IdentityManager) ListActiveIdentities() ([]string, error) {
	files, err := m.Store.ListKeys(m.Store.GetBaseDir())
	if err != nil {
		return nil, &ErrIO{Path: m.Store.GetBaseDir(), Reason: err.Error()}
	}

	var identities []string
	seen := make(map[string]bool)
	for _, name := range files {
		if strings.HasSuffix(name, ".kem.pub") {
			base := strings.TrimSuffix(name, ".kem.pub")
			if !seen[base] {
				identities = append(identities, base)
				seen[base] = true
			}
		}
	}
	return identities, nil
}

func (m *IdentityManager) GetIdentityInfo(name string) (*IdentityInfoResult, error) {
	rawBase, _, err := m.ResolveBaseKeyPath(name)
	if err != nil {
		return nil, err
	}
	// Clean basePath so every derived path has traversal sequences removed.
	basePath := filepath.Clean(rawBase)

	res := &IdentityInfoResult{Name: name}

	if b, err := os.ReadFile(basePath + ".kem.pub"); err == nil {
		res.KEMPub = hex.EncodeToString(b)
	}
	if b, err := os.ReadFile(basePath + ".sig.pub"); err == nil {
		res.SIGPub = hex.EncodeToString(b)
		if pid, err := DerivePeerID(b); err == nil {
			res.PeerID = pid
		}
	}
	return res, nil
}

func (m *IdentityManager) RenameIdentity(oldName, newName string) error {
	oldBase, _, err := m.ResolveBaseKeyPath(oldName)
	if err != nil {
		return err
	}
	newBase, _, err := m.ResolveBaseKeyPath(newName)
	if err != nil {
		return err
	}

	suffixes := []string{".kem.key", ".kem.pub", ".sig.key", ".sig.pub", ".fido2"}
	for _, s := range suffixes {
		_ = os.Rename(oldBase+s, newBase+s)
	}
	return nil
}

// DeleteIdentity removes all key files for a named identity.
// Callers should use Engine.IdentityDelete which securely shreds private key files.
// This lower-level method performs plain removal; secure shredding is done by the engine layer.
func (m *IdentityManager) DeleteIdentity(name string) error {
	rawBase, _, err := m.ResolveBaseKeyPath(name)
	if err != nil {
		return err
	}
	// Clean basePath to eliminate traversal sequences before removing files.
	basePath := filepath.Clean(rawBase)

	allFiles := []string{".kem.key", ".kem.pub", ".sig.key", ".sig.pub", ".fido2"}
	var firstErr error
	for _, s := range allFiles {
		if removeErr := os.Remove(basePath + s); removeErr != nil && !os.IsNotExist(removeErr) {
			if firstErr == nil {
				firstErr = removeErr
			}
		}
	}
	return firstErr
}

// EnsureMaknoonDirs creates the standard directory structure.
func EnsureMaknoonDirs() error {
	home := GetUserHomeDir()
	dirs := []string{
		filepath.Join(home, MaknoonDir),
		filepath.Join(home, MaknoonDir, KeysDir),
		filepath.Join(home, MaknoonDir, VaultsDir),
		filepath.Join(home, MaknoonDir, ProfilesDir),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			return err
		}
	}
	return nil
}

func (id *Identity) Wipe() {
	SafeClear(id.KEMPriv)
	SafeClear(id.SIGPriv)
}
