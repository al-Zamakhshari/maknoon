package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awnumar/memguard"
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

// IsAgentMode returns true if the application is running in non-interactive agent/JSON mode.
func IsAgentMode() bool {
	return os.Getenv("MAKNOON_AGENT_MODE") == "1" || os.Getenv("MAKNOON_JSON") == "1"
}

// Identity represents a full PQC keypair (KEM + SIG) + DHT metadata.
type Identity struct {
	Name      string
	KEMPub    []byte
	KEMPriv   []byte
	SIGPub    []byte
	SIGPriv   []byte
	NostrPub  []byte
	NostrPriv []byte
}

// IdentityManager handles local key storage and resolution.
type IdentityManager struct {
	KeysDir string
}

// NewIdentityManager creates an IdentityManager with default paths.
func NewIdentityManager() *IdentityManager {
	home := GetUserHomeDir()
	return &IdentityManager{
		KeysDir: filepath.Join(home, MaknoonDir, KeysDir),
	}
}

// ResolveKeyPath checks if a key exists locally, in ~/.maknoon/keys/, or in environment variables.
func ResolveKeyPath(path string, envVar string) string {
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	if envVar != "" {
		if env := os.Getenv(envVar); env != "" {
			if _, err := os.Stat(env); err == nil {
				return env
			}
		}
	}
	// Check default keys directory
	if path != "" {
		home := GetUserHomeDir()
		defaultPath := filepath.Join(home, MaknoonDir, KeysDir, path)
		if _, err := os.Stat(defaultPath); err == nil {
			return defaultPath
		}
	}
	return ""
}

// ResolveKeyPath is a convenience method on IdentityManager.
func (m *IdentityManager) ResolveKeyPath(path, envVar string) string {
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		// Check manager's KeysDir
		managedPath := filepath.Join(m.KeysDir, path)
		if _, err := os.Stat(managedPath); err == nil {
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

func (m *IdentityManager) ResolveBaseKeyPath(name string) (string, string, error) {
	if name == "" {
		return "", "", &ErrState{Reason: "identity name required"}
	}

	// 1. If it's an absolute path or contains path separators, use it directly
	if filepath.IsAbs(name) || strings.Contains(name, string(os.PathSeparator)) {
		base := strings.TrimSuffix(name, ".kem.key")
		base = strings.TrimSuffix(base, ".sig.key")
		base = strings.TrimSuffix(base, ".key")
		return base, filepath.Base(base), nil
	}

	// 2. Resolve via name in the managed KeysDir
	return filepath.Join(m.KeysDir, name), name, nil
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
	id.KEMPub, _ = os.ReadFile(basePath + ".kem.pub")
	id.SIGPub, _ = os.ReadFile(basePath + ".sig.pub")
	id.NostrPub, _ = os.ReadFile(basePath + ".nostr.pub")

	// Load and Unlock KEM Private Key
	id.KEMPriv, err = m.LoadPrivateKey(basePath+".kem.key", passphrase, pin, isStdin)
	if err != nil {
		return nil, err
	}

	// Load and Unlock SIG Private Key
	id.SIGPriv, err = m.LoadPrivateKey(basePath+".sig.key", passphrase, pin, isStdin)
	if err != nil {
		id.Wipe()
		return nil, err
	}

	// Load and Unlock Nostr Private Key (Optional)
	nostrPath := basePath + ".nostr.key"
	if _, err := os.Stat(nostrPath); err == nil {
		id.NostrPriv, _ = m.LoadPrivateKey(nostrPath, passphrase, pin, isStdin)
	}

	return id, nil
}

// LoadPrivateKey resolves, reads, and unlocks a single private key.
func (m *IdentityManager) LoadPrivateKey(path string, passphrase []byte, pin string, isStdin bool) ([]byte, error) {
	resolvedPath := m.ResolveKeyPath(path, "")
	if _, err := os.Stat(resolvedPath); err != nil {
		return nil, &ErrState{Reason: fmt.Sprintf("private key not found: %s", path)}
	}

	keyBytes, err := os.ReadFile(resolvedPath)
	if err != nil {
		return nil, err
	}

	if len(keyBytes) > 4 && string(keyBytes[:4]) == MagicHeader {
		unlockedPass, err := m.UnlockPrivateKeyWithFIDOOrPass(passphrase, pin, resolvedPath, isStdin)
		if err != nil {
			return nil, err
		}
		// Decrypt the key stream
		var unlocked bytes.Buffer
		if _, _, err := DecryptStream(bytes.NewReader(keyBytes), &unlocked, unlockedPass, 1, false); err != nil {
			return nil, &ErrCrypto{Reason: fmt.Sprintf("failed to decrypt private key: %v", err)}
		}
		return unlocked.Bytes(), nil
	}

	return keyBytes, nil
}

// UnlockPrivateKeyWithFIDOOrPass handles the logic of getting the unlocking secret.
func (m *IdentityManager) UnlockPrivateKeyWithFIDOOrPass(password []byte, pin string, resolvedPath string, isStdin bool) ([]byte, error) {
	fido2Path := strings.TrimSuffix(resolvedPath, ".key")
	fido2Path = strings.TrimSuffix(fido2Path, ".kem")
	fido2Path = strings.TrimSuffix(fido2Path, ".sig")
	fido2Path += ".fido2"

	if _, err := os.Stat(fido2Path); err == nil {
		raw, err := os.ReadFile(fido2Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read fido2 metadata: %w", err)
		}
		var meta Fido2Metadata
		if err := json.Unmarshal(raw, &meta); err != nil {
			return nil, fmt.Errorf("failed to unmarshal fido2 metadata: %w", err)
		}
		secret, err := Fido2Derive(meta.RPID, meta.CredentialID, pin)
		if err != nil {
			return nil, &ErrAuthentication{Reason: fmt.Sprintf("FIDO2 derivation failed: %v", err)}
		}
		return secret, nil
	}

	if len(password) == 0 {
		return nil, &ErrAuthentication{Reason: "passphrase required to unlock private key"}
	}
	return password, nil
}

// ResolvePublicKey handles handle resolution (@name) and local file paths.
func (m *IdentityManager) ResolvePublicKey(input string, tofu bool) ([]byte, error) {
	if strings.HasPrefix(input, "@") {
		// 1. Check local contacts (Petnames)
		cm, err := NewContactManager()
		if err == nil {
			contacts, _ := cm.List()
			var found []byte
			for _, c := range contacts {
				if c.Petname == input {
					found = c.KEMPubKey
					break
				}
			}
			cm.Close()
			if found != nil {
				return found, nil
			}
		}

		// 2. Check Global Discovery Registry
		reg := NewIdentityRegistry()
		record, err := reg.Resolve(context.Background(), input)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve identity handle: %w", err)
		}
		return record.KEMPubKey, nil
	}

	// 3. Fallback: Direct file path
	resolved := m.ResolveKeyPath(input, "")
	if resolved == "" {
		return nil, &ErrState{Reason: fmt.Sprintf("public key file not found: %s", input)}
	}
	return os.ReadFile(resolved)
}

// ListActiveIdentities returns a list of public key files in the KeysDir.
func (m *IdentityManager) ListActiveIdentities() ([]string, error) {
	files, err := os.ReadDir(m.KeysDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var identities []string
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if strings.HasSuffix(name, ".pub") {
			identities = append(identities, name)
		}
	}
	return identities, nil
}

// EnsureMaknoonDirs creates the default configuration and key directories.
func EnsureMaknoonDirs() error {
	home := GetUserHomeDir()
	base := filepath.Join(home, MaknoonDir)
	dirs := []string{
		base,
		filepath.Join(base, KeysDir),
		filepath.Join(base, VaultsDir),
		filepath.Join(base, ProfilesDir),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return nil
}

func (id *Identity) Wipe() {
	SafeClear(id.KEMPriv)
	SafeClear(id.SIGPriv)
	SafeClear(id.NostrPriv)
}

func SafeClear(b []byte) {
	if b != nil {
		memguard.WipeBytes(b)
	}
}
