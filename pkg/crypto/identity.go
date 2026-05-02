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

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
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

// Identity represents a full PQC keypair (KEM + SIG) + DHT metadata.
type Identity struct {
	Name      string
	KEMPub    []byte
	KEMPriv   SecretBytes
	SIGPub    []byte
	SIGPriv   SecretBytes
	NostrPub  []byte
	NostrPriv SecretBytes
}

// IdentityManager handles local key storage and resolution.
type IdentityManager struct {
	Store    KeyStore
	Contacts *ContactManager
	P2P      P2PService
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
func (m *IdentityManager) SaveIdentity(basePath, baseName string, kemPub, kemPriv, sigPub, sigPriv, nostrPub, nostrPriv, passphrase []byte, profileID byte) error {
	writeKey := func(path string, data []byte, isPrivate bool) error {
		if len(data) == 0 {
			return nil
		}
		finalData := data
		if isPrivate && len(passphrase) > 0 {
			var b bytes.Buffer
			if err := EncryptStream(bytes.NewReader(data), &b, passphrase, FlagNone, 1, profileID); err != nil {
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
	if err := writeKey(basePath+".nostr.key", nostrPriv, true); err != nil {
		return err
	}
	if err := writeKey(basePath+".nostr.pub", nostrPub, false); err != nil {
		return err
	}
	return nil
}

// CreateIdentity generates and saves a new Post-Quantum identity.
func (m *IdentityManager) CreateIdentity(name string, passphrase []byte, pin string, isStdin bool, profile string) (*IdentityResult, error) {
	profileID := byte(1)
	if profile == "aes" {
		profileID = 2
	} else if profile == "conservative" {
		profileID = 3
	}

	if err := EnsureMaknoonDirs(); err != nil {
		return nil, err
	}

	kemPub, kemPriv, sigPub, sigPriv, nostrPub, nostrPriv, err := GeneratePQKeyPair(profileID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypairs: %w", err)
	}

	defer func() {
		SafeClear(kemPriv)
		SafeClear(sigPriv)
		SafeClear(nostrPriv)
	}()

	basePath, baseName, err := m.ResolveBaseKeyPath(name)
	if err != nil {
		return nil, err
	}

	if err := m.SaveIdentity(basePath, baseName, kemPub, kemPriv, sigPub, sigPriv, nostrPub, nostrPriv, passphrase, profileID); err != nil {
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
	id.NostrPub, _ = m.Store.ReadKey(basePath + ".nostr.pub")

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

	// Load and Unlock Nostr Private Key if exists
	if m.Store.Exists(basePath + ".nostr.key") {
		id.NostrPriv, _ = m.LoadPrivateKey(basePath+".nostr.key", passphrase, pin, isStdin)
	}

	return id, nil
}

// LoadPrivateKey handles the decryption of a protected key file.
func (m *IdentityManager) LoadPrivateKey(path string, passphrase []byte, pin string, isStdin bool) ([]byte, error) {
	if !m.Store.Exists(path) {
		return nil, &ErrIO{Path: path, Reason: "key file not found"}
	}

	// Case 1: Decrypt using FIDO2 if .fido2 file exists
	fidoPath := path + ".fido2"
	if m.Store.Exists(fidoPath) {
		return m.UnlockPrivateKeyWithFIDOOrPass(passphrase, pin, path, isStdin)
	}

	// Case 2: Check if key is plain-text or protected
	data, err := m.Store.ReadKey(path)
	if err != nil {
		return nil, &ErrIO{Path: path, Reason: err.Error()}
	}

	// Peek at the first 4 bytes for the magic header
	if len(data) >= 4 && string(data[:4]) == MagicHeader {
		// Protected key
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

func (m *IdentityManager) UnlockPrivateKeyWithFIDOOrPass(password []byte, pin string, resolvedPath string, isStdin bool) ([]byte, error) {
	data, err := m.Store.ReadKey(resolvedPath)
	if err != nil {
		return nil, &ErrIO{Path: resolvedPath, Reason: err.Error()}
	}

	fidoPath := resolvedPath + ".fido2"
	token, err := Fido2Unlock(fidoPath, pin)
	if err != nil {
		// Fallback to passphrase if FIDO fails but passphrase was provided
		if len(password) > 0 {
			var decrypted bytes.Buffer
			_, _, err := DecryptStream(bytes.NewReader(data), &decrypted, password, 1, false)
			if err == nil {
				return decrypted.Bytes(), nil
			}
		}
		return nil, &ErrAuthentication{Reason: fmt.Sprintf("FIDO2 unlock failed: %v", err)}
	}
	defer SafeClear(token)

	var decrypted bytes.Buffer
	_, _, err = DecryptStream(bytes.NewReader(data), &decrypted, token, 1, false)
	if err != nil {
		return nil, &ErrAuthentication{Reason: "FIDO2 token failed to decrypt the key"}
	}

	return decrypted.Bytes(), nil
}

// ResolvePublicKey takes a petname (@handle), a local path, or raw hex and returns the KEM public key.
func (m *IdentityManager) ResolvePublicKey(input string, tofu bool) ([]byte, error) {
	// 1. Handle Petnames (@handle)
	if strings.HasPrefix(input, "@") {
		if m.Contacts == nil {
			return nil, fmt.Errorf("contact manager not initialized")
		}
		c, err := m.Contacts.Get(input)
		if err == nil {
			return c.KEMPubKey, nil
		}
		// 2. DHT/DNS Discovery
		reg := NewIdentityRegistry(nil)
		record, DiscoveryErr := reg.Resolve(context.Background(), input)
		if DiscoveryErr == nil {
			if tofu {
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
		return nil, fmt.Errorf("petname resolution failed: %w (discovery error: %v)", err, DiscoveryErr)
	}

	// 3. Handle Local Paths or Managed Keys
	resolvedPath := input
	if _, err := os.Stat(input); err != nil {
		// Not a direct local path, check the managed store
		if managed, err := m.Store.ResolvePath(input); err == nil {
			resolvedPath = managed
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
	basePath, _, err := m.ResolveBaseKeyPath(name)
	if err != nil {
		return nil, err
	}

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
	if b, err := os.ReadFile(basePath + ".nostr.pub"); err == nil {
		res.NostrPub = hex.EncodeToString(b)
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

	suffixes := []string{".kem.key", ".kem.pub", ".sig.key", ".sig.pub", ".nostr.key", ".nostr.pub", ".fido2"}
	for _, s := range suffixes {
		_ = os.Rename(oldBase+s, newBase+s)
	}
	return nil
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

func (e *Engine) IdentityActive(ectx *EngineContext) ([]string, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return e.Identities.ListActiveIdentities()
}

func (e *Engine) IdentityInfo(ectx *EngineContext, name string) (*IdentityInfoResult, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return e.Identities.GetIdentityInfo(name)
}

func (e *Engine) IdentityRename(ectx *EngineContext, oldName, newName string) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return err
	}
	return e.Identities.RenameIdentity(oldName, newName)
}

func (e *Engine) IdentitySplit(ectx *EngineContext, name string, threshold, shares int, passphrase string) ([]string, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return e.Identities.SplitIdentity(name, threshold, shares, passphrase)
}

func (e *Engine) IdentityCombine(ectx *EngineContext, mnemonics []string, output, passphrase string, noPassword bool) (string, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return "", err
	}
	return e.Identities.CombineIdentity(mnemonics, output, passphrase, noPassword)
}

func (e *Engine) IdentityPublish(ectx *EngineContext, handle string, opts IdentityPublishOptions) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return err
	}
	if err := e.ensureContacts(); err != nil {
		return err
	}
	return e.Identities.IdentityPublish(ectx.Context, handle, opts)
}

func (e *Engine) CreateIdentity(ectx *EngineContext, output string, passphrase []byte, pin string, agent bool, profile string) (*IdentityResult, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return e.Identities.CreateIdentity(output, passphrase, pin, agent, profile)
}

func (id *Identity) Wipe() {
	SafeClear(id.KEMPriv)
	SafeClear(id.SIGPriv)
	SafeClear(id.NostrPriv)
}

// AsLibp2pKey converts the Maknoon signing key to a libp2p private key.
// In v1.x, we support Hybrid SIG (ML-DSA + Ed25519). If an Ed25519 key is bundled,
// we use it directly. Otherwise, we fallback to deterministic derivation.
func (id *Identity) AsLibp2pKey() (libp2pcrypto.PrivKey, error) {
	if len(id.SIGPriv) == 0 {
		return nil, fmt.Errorf("signing key not loaded")
	}

	var edPrivBytes []byte

	// 1. Check for Hybrid Format (ML-DSA-87 + Ed25519)
	// ML-DSA-87 Priv is 4896 bytes, Ed25519 Priv is 64 bytes.
	if len(id.SIGPriv) >= 4896+64 {
		edPrivBytes = id.SIGPriv[4896 : 4896+64]
	} else if len(id.SIGPriv) >= 4032+64 { // ML-DSA-65
		edPrivBytes = id.SIGPriv[4032 : 4032+64]
	} else if len(id.SIGPriv) >= 128+64 { // SLH-DSA
		edPrivBytes = id.SIGPriv[len(id.SIGPriv)-64:]
	} else {
		// 2. Fallback: Deterministic derivation from the first 32 bytes of SIGPriv
		seed := id.SIGPriv
		if len(seed) > 32 {
			seed = seed[:32]
		}
		priv, _, err := libp2pcrypto.GenerateEd25519Key(bytes.NewReader(seed))
		return priv, err
	}

	return libp2pcrypto.UnmarshalEd25519PrivateKey(edPrivBytes)
}

// GetPeerID derives the libp2p PeerID from the identity's signing key.
func (id *Identity) GetPeerID() (peer.ID, error) {
	priv, err := id.AsLibp2pKey()
	if err != nil {
		return "", err
	}

	return peer.IDFromPrivateKey(priv)
}
