package crypto

import (
	"context"
	"io"
	"log/slog"
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
	Events  chan<- EngineEvent
	Policy  SecurityPolicy
	TraceID string
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
// The send is non-blocking: if the consumer is slow and the channel is full, the event is
// dropped silently so the encrypt/decrypt pipeline never stalls.
func (c *EngineContext) Emit(ev EngineEvent) {
	if c == nil || c.Events == nil {
		return
	}
	defer func() { _ = recover() }()
	select {
	case c.Events <- ev:
	default:
		// consumer too slow — drop event silently
	}
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

// IdentityCapabilities handles identity lifecycle and discovery.
type IdentityCapabilities interface {
	IdentityActive(ectx *EngineContext) ([]string, error)
	IdentityInfo(ectx *EngineContext, name string) (*IdentityInfoResult, error)
	IdentityDelete(ectx *EngineContext, name string) error
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
	LoadIdentity(ectx *EngineContext, name string, passphrase []byte, pin string, agent bool) (*Identity, error)
	ResolveKeyPath(ectx *EngineContext, path, envVar string) string
	ResolveBaseKeyPath(ectx *EngineContext, name string) (string, string, error)
}

// VaultManager handles secure credential storage.
type VaultManager interface {
	VaultInitInstitutional(ectx *EngineContext, name string, threshold, shares int, peerIDs []string, passphrase []byte) (*VaultResult, error)
	VaultStatus(ectx *EngineContext, name string) (*VaultResult, error)
	VaultGet(ectx *EngineContext, vaultPath string, service string, passphrase []byte, pin string) (*VaultEntry, error)
	VaultSet(ectx *EngineContext, vaultPath string, entry *VaultEntry, passphrase []byte, pin string, overwrite bool) error
	VaultRename(ectx *EngineContext, oldName, newName string) error
	VaultDelete(ectx *EngineContext, name string) error
	VaultList(ectx *EngineContext, vaultPath string, passphrase []byte) ([]VaultListEntry, error)
	VaultRotate(ectx *EngineContext, vaultPath string, oldPassphrase, newPassphrase []byte) error
	VaultCheckShards(ectx *EngineContext, mnemonics []string) (*VaultResult, error)
	VaultSplit(ectx *EngineContext, vaultPath string, threshold, shares int, passphrase string) ([]string, error)
	VaultRecover(ectx *EngineContext, mnemonics []string, vaultPath string, output string, passphrase string) (string, error)
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

// Signer handles digital signature operations.
type Signer interface {
	Sign(ectx *EngineContext, data []byte, privKey []byte) ([]byte, error)
	Verify(ectx *EngineContext, data []byte, sig []byte, pubKey []byte) (bool, error)
	Aggregate(ectx *EngineContext, signatures [][]byte) ([]byte, error)
	VerifyThreshold(ectx *EngineContext, data []byte, aggregateSig []byte, authorizedKeys [][]byte, threshold int) (bool, error)
}

// KMSService provides enterprise-grade envelope encryption (Key Wrapping).
type KMSService interface {
	Wrap(ectx *EngineContext, pubKey []byte) (DataKey, error)
	Unwrap(ectx *EngineContext, wrappedKey []byte, privKey []byte) ([]byte, error)
}

// DispersalService handles RAID-for-Privacy data dispersal.
type DispersalService interface {
	FragmentFile(ctx *EngineContext, inputPath string, opts FragmentOptions) error
	ReassembleFragments(srcDir string, w io.Writer, authorizedPubKey []byte) error
	ReassembleToPath(ctx *EngineContext, srcDir, outputPath string, authorizedPubKey []byte) error
}

// MaknoonEngine is the primary high-level facade for all Maknoon services.
type MaknoonEngine interface {
	Protector
	IdentityCapabilities
	VaultManager
	Utils
	StateProvider
	Inspector
	Signer
	KMSService
	DispersalService

	Close() error
}
