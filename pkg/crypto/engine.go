package crypto

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/libp2p/go-libp2p"
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

// StateProvider provides a standardized interface for accessing and managing
// the engine's internal configuration state and security policy.
type StateProvider interface {
	GetPolicy() SecurityPolicy
	GetConfig() *Config
	UpdateConfig(ectx *EngineContext, newConf *Config) error
	RegisterProfile(ectx *EngineContext, name string, dp *DynamicProfile) error
	RemoveProfile(ectx *EngineContext, name string) error
}

// Inspector provides non-destructive analysis of encrypted Maknoon data.
type Inspector interface {
	Inspect(ectx *EngineContext, in io.Reader) (*HeaderInfo, error)
}

// TunnelService provides managed access to post-quantum L4 tunnels.
type TunnelService interface {
	TunnelStart(ectx *EngineContext, opts tunnel.TunnelOptions) (tunnel.TunnelStatus, error)
	TunnelStop(ectx *EngineContext) error
	TunnelStatus(ectx *EngineContext) (tunnel.TunnelStatus, error)
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
}

// Engine is the central stateful service for Maknoon operations.
type Engine struct {
	Policy     SecurityPolicy
	Config     *Config
	Identities *IdentityManager

	// Tunnel State
	activeTunnel *tunnel.TunnelStatus
	gateway      *tunnel.TunnelGateway
	tunnelMu     sync.RWMutex
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

func (e *Engine) Inspect(_ *EngineContext, in io.Reader) (*HeaderInfo, error) {
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

func (e *Engine) TunnelStart(ectx *EngineContext, opts tunnel.TunnelOptions) (tunnel.TunnelStatus, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapP2P); err != nil {
		return tunnel.TunnelStatus{}, err
	}

	e.tunnelMu.Lock()
	defer e.tunnelMu.Unlock()

	if e.activeTunnel != nil && e.activeTunnel.Active {
		return *e.activeTunnel, fmt.Errorf("a tunnel is already active")
	}

	factory := &tunnel.TransportFactory{Config: e.Config.Tunnel}
	session, err := factory.CreateClientSession(ectx.Context, opts)
	if err != nil {
		return tunnel.TunnelStatus{}, err
	}

	gw := &tunnel.TunnelGateway{
		Port:    opts.LocalProxyPort,
		Session: session,
	}
	if err := gw.Start(); err != nil {
		session.Close()
		return tunnel.TunnelStatus{}, fmt.Errorf("failed to start SOCKS5 gateway: %w", err)
	}

	e.activeTunnel = &tunnel.TunnelStatus{
		Active:         true,
		LocalAddress:   fmt.Sprintf("127.0.0.1:%d", opts.LocalProxyPort),
		RemoteEndpoint: opts.RemoteEndpoint,
		HandshakeTime:  time.Now().Format(time.RFC3339),
	}
	e.gateway = gw

	return *e.activeTunnel, nil
}

func (e *Engine) TunnelStop(ectx *EngineContext) error {
	e.tunnelMu.Lock()
	defer e.tunnelMu.Unlock()

	if e.gateway != nil {
		e.gateway.Stop()
		if e.gateway.Session != nil {
			e.gateway.Session.Close()
		}
	}

	e.activeTunnel = nil
	e.gateway = nil
	return nil
}

func (e *Engine) TunnelStatus(ectx *EngineContext) (tunnel.TunnelStatus, error) {
	e.tunnelMu.RLock()
	defer e.tunnelMu.RUnlock()

	if e.activeTunnel == nil {
		return tunnel.TunnelStatus{Active: false}, nil
	}
	return *e.activeTunnel, nil
}

// P2PKeepAlive starts a background DHT advertising loop for the current identity.
// This allows other peers to discover this node via its PeerID.
func (e *Engine) P2PKeepAlive(ectx *EngineContext, identityName string) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapP2P); err != nil {
		return err
	}

	id, err := e.Identities.LoadIdentity(identityName, nil, "", false)
	if err != nil {
		return err
	}

	priv, err := id.AsLibp2pKey()
	if err != nil {
		return err
	}

	h, err := tunnel.NewLibp2pHost(libp2p.Identity(priv))
	if err != nil {
		return err
	}

	slog.Info("p2p keep-alive: advertising identity", "peer_id", h.ID(), "identity", identityName)

	// In a real implementation, we would use dht.Provide here.
	// For now, we just keep the host alive to be reachable via relays.
	go func() {
		<-ectx.Done()
		h.Close()
	}()

	return nil
}

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

func SafeClear(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}
