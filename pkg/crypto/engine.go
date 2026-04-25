package crypto

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

// EngineEvent is the base interface for all telemetry events.
type EngineEvent interface{}

// EventEncryptionStarted is emitted when the protection pipeline begins.
type EventEncryptionStarted struct {
	TotalBytes int64
}

// EventDecryptionStarted is emitted when the unprotection pipeline begins.
type EventDecryptionStarted struct {
	TotalBytes int64
}

// EventHandshakeComplete is emitted after the header is successfully processed.
type EventHandshakeComplete struct{}

// EventChunkProcessed is emitted for each successfully processed data chunk.
type EventChunkProcessed struct {
	BytesProcessed int64
	TotalProcessed int64
}

// EventEmitter defines the interface for sending telemetry.
type EventEmitter interface {
	Emit(ev EngineEvent)
}

// EngineContext carries the execution state, telemetry stream, and policy for an operation.
type EngineContext struct {
	context.Context
	Events chan<- EngineEvent
	Policy SecurityPolicy
}

// NewEngineContext creates a new context with an optional event stream.
func NewEngineContext(ctx context.Context, events chan<- EngineEvent, policy SecurityPolicy) *EngineContext {
	if ctx == nil {
		ctx = context.Background()
	}
	return &EngineContext{
		Context: ctx,
		Events:  events,
		Policy:  policy,
	}
}

// Emit safely sends an event to the telemetry stream, preventing panics on closed channels.
func (c *EngineContext) Emit(ev EngineEvent) {
	if c == nil || c.Events == nil {
		return
	}
	defer func() { _ = recover() }()
	c.Events <- ev
}

// Protector handles encryption and decryption pipelines.
type Protector interface {
	Protect(ectx *EngineContext, inputName string, r io.Reader, w io.Writer, opts Options) (byte, error)
	Unprotect(ectx *EngineContext, r io.Reader, w io.Writer, outPath string, opts Options) (byte, error)
	FinalizeRestoration(ectx *EngineContext, pr io.Reader, w io.Writer, flags byte, outPath string, logger *slog.Logger) error
	LoadCustomProfile(ectx *EngineContext, path string) (*DynamicProfile, error)
	GenerateRandomProfile(ectx *EngineContext, id byte) *DynamicProfile
	ValidateProfile(ectx *EngineContext, p *DynamicProfile) error
}

// IdentityService handles identity lifecycle and discovery.
type IdentityService interface {
	IdentityActive(ectx *EngineContext) ([]string, error)
	IdentityInfo(ectx *EngineContext, name string) (string, error)
	IdentityRename(ectx *EngineContext, oldName, newName string) error
	IdentitySplit(ectx *EngineContext, name string, threshold, shares int, passphrase string) ([]string, error)
	IdentityCombine(ectx *EngineContext, mnemonics []string, output string, passphrase string, noPassword bool) (string, error)
	IdentityPublish(ectx *EngineContext, handle string, opts IdentityPublishOptions) error
	ContactAdd(ectx *EngineContext, petname, kemPub, sigPub, note string) error
	ContactList(ectx *EngineContext) ([]*Contact, error)
}

// VaultManager handles secure credential storage.
type VaultManager interface {
	VaultGet(ectx *EngineContext, vaultPath string, service string, passphrase []byte, pin string) (*VaultEntry, error)
	VaultSet(ectx *EngineContext, vaultPath string, entry *VaultEntry, passphrase []byte, pin string) error
	VaultRename(ectx *EngineContext, oldName, newName string) error
	VaultDelete(ectx *EngineContext, name string) error
	VaultList(ectx *EngineContext, vaultPath string) ([]string, error)
	VaultSplit(ectx *EngineContext, vaultPath string, threshold, shares int, passphrase string) ([]string, error)
	VaultRecover(ectx *EngineContext, mnemonics []string, vaultPath string, output string, passphrase string) (string, error)
}

// P2PService handles peer-to-peer transfers.
type P2PService interface {
	P2PSend(ectx *EngineContext, inputName string, r io.Reader, opts P2PSendOptions) (string, <-chan P2PStatus, error)
	P2PReceive(ectx *EngineContext, code string, opts P2PReceiveOptions) (<-chan P2PStatus, error)
	ValidateWormholeURL(ectx *EngineContext, u string) error
}

// Utils provides secure generation helpers.
type Utils interface {
	GeneratePassword(ectx *EngineContext, length int, noSymbols bool) (string, error)
	GeneratePassphrase(ectx *EngineContext, words int, separator string) (string, error)
}

// StateProvider exposes the engine's internal configuration and policy.
type StateProvider interface {
	GetPolicy() SecurityPolicy
	GetConfig() *Config
	UpdateConfig(ectx *EngineContext, newConf *Config) error
	RegisterProfile(ectx *EngineContext, name string, dp *DynamicProfile) error
	RemoveProfile(ectx *EngineContext, name string) error
}

type Inspector interface {
	Inspect(ectx *EngineContext, in io.Reader) (*HeaderInfo, error)
}

// MaknoonEngine is the unified facade for the Maknoon system, composing all specialized services.
type MaknoonEngine interface {
	Protector
	IdentityService
	VaultManager
	P2PService
	Utils
	StateProvider
	Inspector
}

// Engine is the central stateful service for Maknoon operations.
type Engine struct {
	Policy     SecurityPolicy
	Config     *Config
	Identities *IdentityManager
}

func (e *Engine) GetPolicy() SecurityPolicy { return e.Policy }
func (e *Engine) GetConfig() *Config        { return e.Config }

func (e *Engine) UpdateConfig(ectx *EngineContext, newConf *Config) error {
	ectx = e.context(ectx)
	if !ectx.Policy.AllowConfigModification() {
		return &ErrPolicyViolation{Reason: "configuration modification is prohibited under the active policy"}
	}
	if err := newConf.Validate(); err != nil {
		return err
	}
	if err := newConf.Save(); err != nil {
		return err
	}
	e.Config = newConf
	return nil
}

func (e *Engine) RegisterProfile(ectx *EngineContext, name string, dp *DynamicProfile) error {
	ectx = e.context(ectx)
	if !ectx.Policy.AllowConfigModification() {
		return &ErrPolicyViolation{Reason: "profile registration is prohibited under the active policy"}
	}
	if e.Config.Profiles == nil {
		e.Config.Profiles = make(map[string]*DynamicProfile)
	}
	e.Config.Profiles[name] = dp
	RegisterProfile(dp)
	return e.Config.Save()
}

func (e *Engine) RemoveProfile(ectx *EngineContext, name string) error {
	ectx = e.context(ectx)
	if !ectx.Policy.AllowConfigModification() {
		return &ErrPolicyViolation{Reason: "profile removal is prohibited under the active policy"}
	}
	if _, ok := e.Config.Profiles[name]; !ok {
		return fmt.Errorf("profile '%s' not found", name)
	}
	delete(e.Config.Profiles, name)
	return e.Config.Save()
}

func (e *Engine) Inspect(ectx *EngineContext, in io.Reader) (*HeaderInfo, error) {
	ectx = e.context(ectx)
	// Non-destructive read of the header
	magic, profile, flags, recipients, err := ReadHeader(in, false)
	if err != nil {
		return nil, err
	}

	return &HeaderInfo{
		Magic:          magic,
		ProfileID:      profile,
		Flags:          flags,
		RecipientCount: recipients,
		IsCompressed:   flags&FlagCompress != 0,
		IsArchive:      flags&FlagArchive != 0,
		IsSigned:       flags&FlagSigned != 0,
		IsStealth:      flags&FlagStealth != 0,
	}, nil
}

// context ensures a valid context and policy are always available.
func (e *Engine) context(ectx *EngineContext) *EngineContext {
	if ectx == nil {
		return &EngineContext{
			Context: context.Background(),
			Policy:  e.Policy,
		}
	}
	if ectx.Policy == nil {
		ectx.Policy = e.Policy
	}
	if ectx.Context == nil {
		ectx.Context = context.Background()
	}
	return ectx
}

func (e *Engine) enforce(ectx *EngineContext, cap Capability) error {
	if !ectx.Policy.HasCapability(cap) {
		return &ErrPolicyViolation{Reason: fmt.Sprintf("capability '%s' is prohibited under the active policy", cap)}
	}
	return nil
}

// NewEngine creates a new Engine with the specified policy and loaded config.
func NewEngine(policy SecurityPolicy) (*Engine, error) {
	conf, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize engine config: %w", err)
	}

	return &Engine{
		Policy:     policy,
		Config:     conf,
		Identities: NewIdentityManager(),
	}, nil
}

func (e *Engine) GeneratePassword(ectx *EngineContext, length int, noSymbols bool) (string, error) {
	return GeneratePassword(length, noSymbols)
}

func (e *Engine) GeneratePassphrase(ectx *EngineContext, words int, separator string) (string, error) {
	return GeneratePassphrase(words, separator)
}

// bufferPool reduces GC pressure during streaming.
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, ChunkSize+256) // Extra padding for AEAD tags
		return &b
	},
}

// SafeClear securely wipes sensitive bytes.
func SafeClear(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}
