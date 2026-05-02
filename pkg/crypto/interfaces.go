package crypto

import (
	"context"
	"io"
	"log/slog"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
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
	Protect(ectx *EngineContext, inputName string, r io.Reader, w io.Writer, opts Options) (EncryptResult, error)
	Unprotect(ectx *EngineContext, r io.Reader, w io.Writer, outPath string, opts Options) (DecryptResult, error)
	FinalizeRestoration(ectx *EngineContext, pr io.Reader, w io.Writer, flags byte, outPath string, logger *slog.Logger) error
	LoadCustomProfile(ectx *EngineContext, path string) (*DynamicProfile, error)
	GenerateRandomProfile(ectx *EngineContext, id byte) *DynamicProfile
	ValidateProfile(ectx *EngineContext, p *DynamicProfile) error
}

// IdentityService handles identity lifecycle and discovery.
type IdentityService interface {
	IdentityActive(ectx *EngineContext) ([]string, error)
	IdentityInfo(ectx *EngineContext, name string) (*IdentityInfoResult, error)
	IdentityRename(ectx *EngineContext, oldName, newName string) error
	IdentitySplit(ectx *EngineContext, name string, threshold, shares int, passphrase string) ([]string, error)
	IdentityCombine(ectx *EngineContext, mnemonics []string, output string, passphrase string, noPassword bool) (string, error)
	IdentityPublish(ectx *EngineContext, handle string, opts IdentityPublishOptions) error
	CreateIdentity(ectx *EngineContext, output string, passphrase []byte, pin string, agent bool, profile string) (*IdentityResult, error)
	ContactAdd(ectx *EngineContext, petname, kemPub, sigPub, note string) error
	ContactList(ectx *EngineContext) ([]*Contact, error)
	ContactDelete(ectx *EngineContext, petname string) error

	// Key Resolution and Loading
	ResolvePublicKey(ectx *EngineContext, input string, tofu bool) ([]byte, error)
	LoadPrivateKey(ectx *EngineContext, path string, passphrase []byte, pin string, agent bool) ([]byte, error)
	ResolveKeyPath(ectx *EngineContext, path, envVar string) string
	ResolveBaseKeyPath(ectx *EngineContext, name string) (string, string, error)
}

// VaultManager handles secure credential storage.
type VaultManager interface {
	VaultGet(ectx *EngineContext, vaultPath string, service string, passphrase []byte, pin string) (*VaultEntry, error)
	VaultSet(ectx *EngineContext, vaultPath string, entry *VaultEntry, passphrase []byte, pin string, overwrite bool) error
	VaultRename(ectx *EngineContext, oldName, newName string) error
	VaultDelete(ectx *EngineContext, name string) error
	VaultList(ectx *EngineContext, vaultPath string, passphrase []byte) ([]VaultListEntry, error)
	VaultSplit(ectx *EngineContext, vaultPath string, threshold, shares int, passphrase string) ([]string, error)
	VaultRecover(ectx *EngineContext, mnemonics []string, vaultPath string, output string, passphrase string) (string, error)
}

// P2PService handles peer-to-peer transfers.
type P2PService interface {
	P2PSend(ectx *EngineContext, identityName string, inputName string, r io.Reader, opts P2PSendOptions) (string, <-chan P2PStatus, error)
	P2PReceive(ectx *EngineContext, identityName string, code string, opts P2PReceiveOptions) (<-chan P2PStatus, error)
	ChatStart(ectx *EngineContext, identityName string, target string) (*P2PChatSession, error)
	ValidateWormholeURL(ectx *EngineContext, u string) error
}

// Utils provides secure generation helpers.
type Utils interface {
	GeneratePassword(ectx *EngineContext, length int, noSymbols bool) (string, error)
	GeneratePassphrase(ectx *EngineContext, words int, separator string) (string, error)
	SecureDelete(path string) error
}

// StateProvider provides a standardized interface for accessing and managing
// the engine's internal configuration state and security policy.
type StateProvider interface {
	GetPolicy() SecurityPolicy
	GetConfig() *Config
	UpdateConfig(ectx *EngineContext, newConf *Config) error
	RegisterProfile(ectx *EngineContext, name string, dp *DynamicProfile) error
	RemoveProfile(ectx *EngineContext, name string) error
	Diagnostic() DiagnosticResult
	NetworkStatus(ectx *EngineContext) (NetStatusResult, error)
	AuditExport(ectx *EngineContext) ([]AuditEntry, error)
}

// Inspector provides non-destructive analysis of encrypted Maknoon data.
type Inspector interface {
	Inspect(ectx *EngineContext, in io.Reader, stealth bool) (*HeaderInfo, error)
}

// TunnelService provides managed access to post-quantum L4 tunnels.
type TunnelService interface {
	TunnelStart(ectx *EngineContext, opts tunnel.TunnelOptions) (tunnel.TunnelStatus, error)
	TunnelStop(ectx *EngineContext) error
	TunnelStatus(ectx *EngineContext) (tunnel.TunnelStatus, error)
	TunnelListen(ectx *EngineContext, addr string, mode string, identity string) (NetworkResult, error)
}

// ChatService handles persistent identity-bound chat missions.
type ChatService interface {
	ChatStart(ectx *EngineContext, identityName string, target string) (*P2PChatSession, error)
}

// Signer handles digital signature operations.
type Signer interface {
	Sign(ectx *EngineContext, data []byte, privKey []byte) ([]byte, error)
	Verify(ectx *EngineContext, data []byte, sig []byte, pubKey []byte) (bool, error)
}

// KMSService provides enterprise-grade envelope encryption (Key Wrapping).
type KMSService interface {
	Wrap(ectx *EngineContext, pubKey []byte) (DataKey, error)
	Unwrap(ectx *EngineContext, wrappedKey []byte, privKey []byte) ([]byte, error)
}

// MaknoonEngine is the primary high-level facade for all Maknoon services.
type MaknoonEngine interface {
	Protector
	IdentityService
	VaultManager
	P2PService
	Utils
	StateProvider
	Inspector
	TunnelService
	ChatService
	Signer
	KMSService

	Close() error
}
