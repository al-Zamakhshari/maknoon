package crypto

import (
	"bytes"
	"context"
	"encoding/binary"
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

// SaveIdentity persists an identity's keys to disk, optionally encrypted.
func (m *IdentityManager) SaveIdentity(basePath, baseName string, kemPub, kemPriv, sigPub, sigPriv, nostrPub, nostrPriv, passphrase []byte, profileID byte) error {
	writeKey := func(path string, data []byte, isPrivate bool) error {
		if len(data) == 0 {
			return nil
		}
		finalData := data
		if isPrivate {
			var b bytes.Buffer
			if err := EncryptStream(bytes.NewReader(data), &b, passphrase, FlagNone, 1, profileID); err != nil {
				return err
			}
			finalData = b.Bytes()
		}
		mode := os.FileMode(0644)
		if isPrivate {
			mode = 0600
		}
		return os.WriteFile(path, finalData, mode)
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
		return nil, err
	}

	// Load and Unlock Nostr Private Key if exists
	if _, err := os.Stat(basePath + ".nostr.key"); err == nil {
		id.NostrPriv, _ = m.LoadPrivateKey(basePath+".nostr.key", passphrase, pin, isStdin)
	}

	return id, nil
}

// LoadPrivateKey handles the decryption of a protected key file.
func (m *IdentityManager) LoadPrivateKey(path string, passphrase []byte, pin string, isStdin bool) ([]byte, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, &ErrIO{Path: path, Reason: "key file not found"}
	}

	// Resolve the real path
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolvedPath = path
	}

	// Case 1: Decrypt using FIDO2 if .fido2 file exists
	fidoPath := resolvedPath + ".fido2"
	if _, err := os.Stat(fidoPath); err == nil {
		return m.UnlockPrivateKeyWithFIDOOrPass(passphrase, pin, resolvedPath, isStdin)
	}

	// Case 2: Standard decryption with passphrase
	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		return nil, &ErrIO{Path: resolvedPath, Reason: err.Error()}
	}

	var decrypted bytes.Buffer
	_, _, err = DecryptStream(bytes.NewReader(data), &decrypted, passphrase, 1, false)
	if err != nil {
		return nil, &ErrAuthentication{Reason: fmt.Sprintf("failed to unlock key: %v", err)}
	}

	return decrypted.Bytes(), nil
}

func (m *IdentityManager) UnlockPrivateKeyWithFIDOOrPass(password []byte, pin string, resolvedPath string, isStdin bool) ([]byte, error) {
	data, err := os.ReadFile(resolvedPath)
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
		cm, err := NewContactManager()
		if err != nil {
			return nil, err
		}
		defer cm.Close()
		c, err := cm.Get(input)
		if err == nil {
			return c.KEMPubKey, nil
		}
		// 2. DHT/DNS Discovery
		reg := NewIdentityRegistry(nil)
		record, DiscoveryErr := reg.Resolve(context.Background(), input)
		if DiscoveryErr == nil {
			if tofu {
				_ = cm.Add(&Contact{
					Petname:   input,
					KEMPubKey: record.KEMPubKey,
					SIGPubKey: record.SIGPubKey,
					AddedAt:   time.Now(),
					Notes:     "Automatically added via discovery (TOFU)",
				})
			}
			return record.KEMPubKey, nil
		}
		return nil, fmt.Errorf("identity discovered failed: %v", DiscoveryErr)
	}

	// 3. Handle Local Paths
	if _, err := os.Stat(input); err == nil {
		return os.ReadFile(input)
	}

	// 4. Handle Raw Hex
	b, err := hex.DecodeString(input)
	if err == nil && (len(b) == 1184 || len(b) == 32) { // Kyber1024 or similar
		return b, nil
	}

	return nil, fmt.Errorf("unable to resolve public key from: %s", input)
}

func (m *IdentityManager) ListActiveIdentities() ([]string, error) {
	files, err := os.ReadDir(m.KeysDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, &ErrIO{Path: m.KeysDir, Reason: err.Error()}
	}

	var identities []string
	seen := make(map[string]bool)
	for _, f := range files {
		name := f.Name()
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

func (m *IdentityManager) GetIdentityInfo(name string) (string, error) {
	basePath, _, err := m.ResolveBaseKeyPath(name)
	if err != nil {
		return "", err
	}

	info := fmt.Sprintf("Identity: %s\n", name)
	if b, err := os.ReadFile(basePath + ".kem.pub"); err == nil {
		info += fmt.Sprintf("  - KEM Public Key: %x\n", b)
	}
	if b, err := os.ReadFile(basePath + ".sig.pub"); err == nil {
		info += fmt.Sprintf("  - SIG Public Key: %x\n", b)
	}
	if b, err := os.ReadFile(basePath + ".nostr.pub"); err == nil {
		info += fmt.Sprintf("  - Nostr Public Key: %x\n", b)
	}

	return info, nil
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

func (m *IdentityManager) SplitIdentity(name string, threshold, shares int, passphrase string) ([]string, error) {
	// 1. Load the identity
	id, err := m.LoadIdentity(name, []byte(passphrase), "", false)
	if err != nil {
		return nil, err
	}
	defer id.Wipe()

	// 2. Pack the keys
	blob := make([]byte, 12+len(id.KEMPriv)+len(id.SIGPriv)+len(id.NostrPriv))
	offset := 0
	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(len(id.KEMPriv)))
	copy(blob[offset+4:offset+4+len(id.KEMPriv)], id.KEMPriv)
	offset += 4 + len(id.KEMPriv)

	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(len(id.SIGPriv)))
	copy(blob[offset+4:offset+4+len(id.SIGPriv)], id.SIGPriv)
	offset += 4 + len(id.SIGPriv)

	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(len(id.NostrPriv)))
	copy(blob[offset+4:], id.NostrPriv)

	defer SafeClear(blob)

	// 3. Split
	shards, err := SplitSecret(blob, threshold, shares)
	if err != nil {
		return nil, err
	}

	var results []string
	for _, s := range shards {
		results = append(results, s.ToMnemonic())
	}
	return results, nil
}

func (m *IdentityManager) CombineIdentity(mnemonics []string, output, passphrase string, noPassword bool) (string, error) {
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
	defer SafeClear(combined)

	// Unpack
	offset := 0
	kemLen := binary.BigEndian.Uint32(combined[offset : offset+4])
	kemPriv := combined[offset+4 : offset+4+int(kemLen)]
	offset += 4 + int(kemLen)

	sigLen := binary.BigEndian.Uint32(combined[offset : offset+4])
	sigPriv := combined[offset+4 : offset+4+int(sigLen)]
	offset += 4 + int(sigLen)

	nostrLen := binary.BigEndian.Uint32(combined[offset : offset+4])
	nostrPriv := combined[offset+4 : offset+4+int(nostrLen)]

	// Store
	im := NewIdentityManager()
	basePath := filepath.Join(im.KeysDir, output)
	if err := os.MkdirAll(im.KeysDir, 0700); err != nil {
		return "", err
	}

	// Encrypt and save
	pass := []byte(passphrase)
	if noPassword {
		pass = nil
	}

	// Helper to encrypt and save a key
	saveKey := func(key []byte, suffix string) error {
		var encrypted bytes.Buffer
		err := EncryptStream(bytes.NewReader(key), &encrypted, pass, 0, 1, 0)
		if err != nil {
			return err
		}
		return os.WriteFile(basePath+suffix, encrypted.Bytes(), 0600)
	}

	if err := saveKey(kemPriv, ".kem.key"); err != nil {
		return "", err
	}
	if err := saveKey(sigPriv, ".sig.key"); err != nil {
		return "", err
	}
	if len(nostrPriv) > 0 {
		if err := saveKey(nostrPriv, ".nostr.key"); err != nil {
			return "", err
		}
	}

	return basePath, nil
}

// IdentityPublishOptions settings for publishing an identity.
type IdentityPublishOptions struct {
	Name       string // Local identity name
	Passphrase string // Passphrase to unlock local identity
	Local      bool   // Add to local contacts
	DNS        bool   // Publish to DNS (via DHT)
	Desec      bool   // Publish to deSEC
	DesecToken string // deSEC API token
	Nostr      bool   // Publish to Nostr
}

func (m *IdentityManager) IdentityPublish(ctx context.Context, handle string, opts IdentityPublishOptions) error {
	if !strings.HasPrefix(handle, "@") {
		return fmt.Errorf("handle must start with @")
	}

	name := "default"
	if opts.Name != "" {
		name = opts.Name
	}

	// 1. Get active identity
	basePath, _, _ := m.ResolveBaseKeyPath(name)
	var pin string
	if _, err := os.Stat(basePath + ".fido2"); err == nil {
		// PIN might be required, but library-first assumes non-interactive for now
	}

	id, err := m.LoadIdentity(name, []byte(opts.Passphrase), pin, false)
	if err != nil {
		return err
	}
	defer id.Wipe()

	// 2. Create and sign record
	record := &IdentityRecord{
		Handle:    handle,
		KEMPubKey: id.KEMPub,
		SIGPubKey: id.SIGPub,
		Timestamp: time.Now(),
	}

	if err := record.Sign(id.SIGPriv); err != nil {
		return fmt.Errorf("failed to sign identity record: %w", err)
	}

	// 3. Dispatch to registries
	if opts.Local {
		cm, err := NewContactManager()
		if err != nil {
			return err
		}
		defer cm.Close()

		return cm.Add(&Contact{
			Petname:   handle,
			KEMPubKey: record.KEMPubKey,
			SIGPubKey: record.SIGPubKey,
			AddedAt:   time.Now(),
		})
	}

	if opts.Desec {
		token := opts.DesecToken
		if token == "" {
			token = os.Getenv("DESEC_TOKEN")
		}
		if token == "" {
			return fmt.Errorf("deSEC token required")
		}

		dnsReg := NewDNSRegistry()
		return dnsReg.PublishWithKey(ctx, record, []byte(token))
	}

	// Default to Nostr
	if opts.Nostr || (!opts.DNS && !opts.Desec) {
		nostrReg := NewNostrRegistry()
		if len(id.NostrPriv) == 0 {
			return fmt.Errorf("nostr private key not found")
		}
		return nostrReg.PublishWithKey(ctx, record, id.NostrPriv)
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

func (e *Engine) IdentityInfo(ectx *EngineContext, name string) (string, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return "", err
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
	return e.Identities.IdentityPublish(ectx.Context, handle, opts)
}

func (e *Engine) ContactAdd(ectx *EngineContext, petname, kemPub, sigPub, note string) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return err
	}
	cm, err := NewContactManager()
	if err != nil {
		return err
	}
	defer cm.Close()

	kp, _ := hex.DecodeString(kemPub)
	sp, _ := hex.DecodeString(sigPub)

	return cm.Add(&Contact{
		Petname:   petname,
		KEMPubKey: kp,
		SIGPubKey: sp,
		Notes:     note,
		AddedAt:   time.Now(),
	})
}

func (e *Engine) ContactList(ectx *EngineContext) ([]*Contact, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	cm, err := NewContactManager()
	if err != nil {
		return nil, err
	}
	defer cm.Close()
	return cm.List()
}

func (id *Identity) Wipe() {
	SafeClear(id.KEMPriv)
	SafeClear(id.SIGPriv)
	SafeClear(id.NostrPriv)
}

// AsLibp2pKey converts the Maknoon signing key to a libp2p private key.
// In v3.1, we derive a deterministic Ed25519 key from the ML-DSA private key
// to ensure compatibility with the libp2p ecosystem while maintaining PQC roots.
func (id *Identity) AsLibp2pKey() (libp2pcrypto.PrivKey, error) {
	if len(id.SIGPriv) == 0 {
		return nil, fmt.Errorf("signing key not loaded")
	}

	// We use the first 32 bytes of the SIGPriv (the seed) to create a deterministic Ed25519 key.
	// This ensures that the same Maknoon Identity always produces the same PeerID.
	seed := id.SIGPriv
	if len(seed) > 32 {
		seed = seed[:32]
	}

	priv, _, err := libp2pcrypto.GenerateEd25519Key(bytes.NewReader(seed))
	if err != nil {
		return nil, fmt.Errorf("failed to generate libp2p key: %w", err)
	}

	return priv, nil
}

// GetPeerID derives the libp2p PeerID from the identity's signing key.
func (id *Identity) GetPeerID() (peer.ID, error) {
	priv, err := id.AsLibp2pKey()
	if err != nil {
		return "", err
	}

	return peer.IDFromPrivateKey(priv)
}
