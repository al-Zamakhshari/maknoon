package crypto

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/libp2p/go-libp2p"
)

// Engine is the central stateful service for Maknoon operations.
type Engine struct {
	Policy     SecurityPolicy
	Config     *Config
	Identities *IdentityManager
	Vaults     VaultStore
	Logger     *slog.Logger

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

	var libp2pOpts []libp2p.Option
	if opts.P2PMode && opts.Identity != "" {
		id, err := e.Identities.LoadIdentity(opts.Identity, nil, "", false)
		if err != nil {
			return tunnel.TunnelStatus{}, err
		}
		priv, err := id.AsLibp2pKey()
		if err != nil {
			return tunnel.TunnelStatus{}, err
		}
		libp2pOpts = append(libp2pOpts, libp2p.Identity(priv))
	}

	factory := &tunnel.TransportFactory{Config: e.Config.Tunnel}
	session, err := factory.CreateClientSession(ectx.Context, opts, libp2pOpts...)
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

	remote := opts.RemoteEndpoint
	if remote == "" {
		remote = opts.P2PAddr
	}
	if remote == "" {
		remote = "unknown"
	}

	e.activeTunnel = &tunnel.TunnelStatus{
		Active:         true,
		LocalAddress:   fmt.Sprintf("127.0.0.1:%d", opts.LocalProxyPort),
		RemoteEndpoint: remote,
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

func (e *Engine) ChatStart(ectx *EngineContext, identityName string, target string) (*P2PChatSession, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapP2P); err != nil {
		return nil, err
	}

	// 1. Load active identity
	idName := identityName
	if idName == "" {
		idName = e.GetConfig().DefaultIdentity
	}
	if idName == "" {
		idName = "default"
	}
	id, err := e.Identities.LoadIdentity(idName, nil, "", false)
	if err != nil {
		return nil, err
	}

	// 2. Derive libp2p key
	priv, err := id.AsLibp2pKey()
	if err != nil {
		return nil, err
	}

	// 3. Start libp2p host
	h, err := tunnel.NewLibp2pHost(libp2p.Identity(priv))
	if err != nil {
		return nil, err
	}

	sess := NewP2PChatSession(h)

	if target == "" {
		_, err = sess.StartHost(ectx.Context)
	} else {
		// If target starts with @, resolve it
		if strings.HasPrefix(target, "@") {
			cm, err := NewContactManager()
			if err != nil {
				return nil, err
			}
			defer cm.Close()
			c, err := cm.Get(target)
			if err != nil {
				return nil, err
			}
			if c.PeerID == "" {
				return nil, fmt.Errorf("contact %s has no PeerID", target)
			}
			target = c.PeerID
		}
		err = sess.StartJoin(ectx.Context, target)
	}

	if err != nil {
		h.Close()
		return nil, err
	}

	return sess, nil
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

func NewEngine(policy SecurityPolicy, idMgr *IdentityManager, conf *Config, vaultStore VaultStore, logger *slog.Logger) (*Engine, error) {
	if conf == nil {
		var err error
		conf, err = LoadConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize engine config: %w", err)
		}
	}

	if idMgr == nil {
		idMgr = NewIdentityManager()
	}

	if vaultStore == nil {
		vaultStore = &FileSystemVaultStore{
			BaseDir: conf.Paths.VaultsDir,
		}
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &Engine{
		Policy:     policy,
		Config:     conf,
		Identities: idMgr,
		Vaults:     vaultStore,
		Logger:     logger,
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
