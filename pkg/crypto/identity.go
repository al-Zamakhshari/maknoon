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
	"golang.org/x/term"
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

// Identity represents a full PQC keypair (KEM + SIG) + DHT metadata.
type Identity struct {
	Name      string
	KEMPub    []byte
	KEMPriv   []byte
	SIGPub    []byte
	SIGPriv   []byte
	NostrPub  []byte // Secp256k1 for Nostr
	NostrPriv []byte
}

func (id *Identity) Wipe() {
	SafeClear(id.KEMPriv)
	SafeClear(id.SIGPriv)
	SafeClear(id.NostrPriv)
}

// IdentityManager handles resolution and discovery of cryptographic identities.
type IdentityManager struct {
	KeysDir string
	HomeDir string
}

// NewIdentityManager creates a new manager with default paths.
func NewIdentityManager() *IdentityManager {
	home, _ := os.UserHomeDir()
	return &IdentityManager{
		KeysDir: filepath.Join(home, MaknoonDir, KeysDir),
		HomeDir: home,
	}
}

// ResolveKeyPath checks if a key exists locally, in the manager's keys directory, or in environment variables.
func (m *IdentityManager) ResolveKeyPath(path string, envVar string) string {
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		maknoonPath := filepath.Join(m.KeysDir, path)
		if _, err := os.Stat(maknoonPath); err == nil {
			return maknoonPath
		}
	}

	if envVar != "" {
		if env := os.Getenv(envVar); env != "" {
			if _, err := os.Stat(env); err == nil {
				return env
			}
		}
	}

	return path
}

// ResolveBaseKeyPath resolves the base path and name for an identity.
func (m *IdentityManager) ResolveBaseKeyPath(output string) (string, string, error) {
	if err := os.MkdirAll(m.KeysDir, 0700); err != nil {
		return "", "", fmt.Errorf("failed to create keys directory: %w", err)
	}

	if output != "" && strings.Contains(output, string(os.PathSeparator)) {
		return output, filepath.Base(output), nil
	}

	baseName := "id_maknoon"
	if output != "" {
		baseName = filepath.Base(output)
	}
	return filepath.Join(m.KeysDir, baseName), baseName, nil
}

// LoadIdentity handles the full flow of resolving and unlocking an identity.
func (m *IdentityManager) LoadIdentity(name string, passphrase []byte, isStdin bool) (*Identity, error) {
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
	id.KEMPriv, err = m.LoadPrivateKey(basePath+".kem.key", passphrase, isStdin)
	if err != nil {
		return nil, fmt.Errorf("failed to load KEM key: %w", err)
	}

	// Load and Unlock SIG Private Key
	id.SIGPriv, err = m.LoadPrivateKey(basePath+".sig.key", passphrase, isStdin)
	if err != nil {
		id.Wipe()
		return nil, fmt.Errorf("failed to load SIG key: %w", err)
	}

	// Load and Unlock Nostr Private Key (Optional)
	nostrPath := basePath + ".nostr.key"
	if _, err := os.Stat(nostrPath); err == nil {
		id.NostrPriv, _ = m.LoadPrivateKey(nostrPath, passphrase, isStdin)
	}

	return id, nil
}

// LoadPrivateKey resolves, reads, and unlocks a single private key.
func (m *IdentityManager) LoadPrivateKey(path string, passphrase []byte, isStdin bool) ([]byte, error) {
	resolvedPath := m.ResolveKeyPath(path, "")
	if _, err := os.Stat(resolvedPath); err != nil {
		return nil, fmt.Errorf("private key not found: %s", path)
	}

	keyBytes, err := os.ReadFile(resolvedPath)
	if err != nil {
		return nil, err
	}

	if len(keyBytes) > 4 && string(keyBytes[:4]) == MagicHeader {
		unlockedPass, err := m.UnlockPrivateKeyWithFIDOOrPass(passphrase, resolvedPath, isStdin)
		if err != nil {
			return nil, err
		}
		// Decrypt the key stream
		var unlocked bytes.Buffer
		if _, _, err := DecryptStream(bytes.NewReader(keyBytes), &unlocked, unlockedPass, 1, false); err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
		return unlocked.Bytes(), nil
	}

	return keyBytes, nil
}

// UnlockPrivateKeyWithFIDOOrPass handles the logic of getting the unlocking secret.
func (m *IdentityManager) UnlockPrivateKeyWithFIDOOrPass(password []byte, resolvedPath string, isStdin bool) ([]byte, error) {
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
		return Fido2Derive(meta.RPID, meta.CredentialID)
	}

	if len(password) == 0 {
		if isStdin {
			return nil, fmt.Errorf("passphrase required via MAKNOON_PASSPHRASE or -s to unlock private key")
		}
		fmt.Print("Enter passphrase to unlock your private key: ")
		p, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, err
		}
		password = p
	}
	return password, nil
}

// ResolvePublicKey handles handle resolution (@name) and local file paths.
func (m *IdentityManager) ResolvePublicKey(input string) ([]byte, error) {
	if strings.HasPrefix(input, "@") {
		// 1. Check local contacts (Petnames)
		cm, err := NewContactManager()
		if err == nil {
			contact, err := cm.Get(input)
			if err == nil {
				cm.Close()
				return contact.KEMPubKey, nil
			}
			cm.Close()
		}

		// 2. Fallback to Global Registry (Local Bolt Prototype)
		if GlobalRegistry != nil {
			record, err := GlobalRegistry.Resolve(context.Background(), input)
			if err == nil {
				return record.KEMPubKey, nil
			}
		}

		// 3. Try Nostr if it's a nostr handle
		if strings.HasPrefix(input, "@nostr:") || strings.HasPrefix(input, "npub1") {
			nostrReg := NewNostrRegistry()
			record, err := nostrReg.Resolve(context.Background(), input)
			if err == nil {
				return record.KEMPubKey, nil
			}
			return nil, fmt.Errorf("failed to resolve nostr handle: %w", err)
		}

		// 4. Last resort: Try DNS resolution directly
		dnsReg := NewDNSRegistry()
		record, err := dnsReg.Resolve(context.Background(), input)
		if err == nil {
			return record.KEMPubKey, nil
		}

		return nil, fmt.Errorf("failed to resolve handle: %s (tried local, registry, and dns)", input)
	}

	resolvedPath := m.ResolveKeyPath(input, "")
	if resolvedPath == "" {
		return nil, fmt.Errorf("public key not found: %s", input)
	}
	return os.ReadFile(resolvedPath)
}

// ListActiveIdentities returns absolute paths to all available public keys.
func (m *IdentityManager) ListActiveIdentities() ([]string, error) {
	var keys []string
	if _, err := os.Stat(m.KeysDir); os.IsNotExist(err) {
		return keys, nil
	}

	files, err := os.ReadDir(m.KeysDir)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".pub") {
			keys = append(keys, filepath.Join(m.KeysDir, f.Name()))
		}
	}
	return keys, nil
}

// Helper functions for easy access

func ResolveKeyPath(path string, envVar string) string {
	return NewIdentityManager().ResolveKeyPath(path, envVar)
}

func GetDefaultVaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, MaknoonDir, VaultsDir, "default.db")
}

func EnsureMaknoonDirs() error {
	return NewIdentityManager().ensureDirs()
}

func (m *IdentityManager) ensureDirs() error {
	base := filepath.Join(m.HomeDir, MaknoonDir)
	dirs := []string{
		m.KeysDir,
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

func ValidatePath(path string, restricted bool) error {
	if path == "-" || path == "" {
		return nil
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	evalPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		parentEval, err2 := filepath.EvalSymlinks(filepath.Dir(absPath))
		if err2 == nil {
			evalPath = filepath.Join(parentEval, filepath.Base(absPath))
		} else {
			evalPath = absPath
		}
	}

	if restricted {
		home, _ := os.UserHomeDir()
		evalHome, _ := filepath.EvalSymlinks(home)
		tmp := os.TempDir()
		evalTmp, _ := filepath.EvalSymlinks(tmp)

		if !strings.HasPrefix(evalPath, evalHome) && !strings.HasPrefix(evalPath, evalTmp) {
			return fmt.Errorf("security policy: arbitrary file paths outside home or temp are prohibited")
		}
	}

	return nil
}

func SafeClear(b []byte) {
	if b != nil {
		memguard.WipeBytes(b)
	}
}
