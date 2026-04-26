package crypto

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/psanford/wormhole-william/wormhole"
)

// EngineEvent is the base interface for all telemetry events.
type EngineEvent interface{}

// Telemetry Events
type EventEncryptionStarted struct{ TotalBytes int64 }
type EventDecryptionStarted struct{ TotalBytes int64 }
type EventHandshakeComplete struct{}
type EventChunkProcessed struct {
	BytesProcessed int64
	TotalProcessed int64
}

// EngineContext carries the execution state and policy for an operation.
type EngineContext struct {
	context.Context
	Events chan<- EngineEvent
	Policy SecurityPolicy
}

func NewEngineContext(ctx context.Context, events chan<- EngineEvent, policy SecurityPolicy) *EngineContext {
	if ctx == nil { ctx = context.Background() }
	return &EngineContext{Context: ctx, Events: events, Policy: policy}
}

func (c *EngineContext) Emit(ev EngineEvent) {
	if c == nil || c.Events == nil { return }
	defer func() { _ = recover() }()
	c.Events <- ev
}

// Interface Definitions
type Protector interface {
	Protect(ectx *EngineContext, inputName string, r io.Reader, w io.Writer, opts Options) (byte, error)
	Unprotect(ectx *EngineContext, r io.Reader, w io.Writer, outPath string, opts Options) (byte, error)
	FinalizeRestoration(ectx *EngineContext, pr io.Reader, w io.Writer, flags byte, outPath string, logger *slog.Logger) error
	LoadCustomProfile(ectx *EngineContext, path string) (*DynamicProfile, error)
	GenerateRandomProfile(ectx *EngineContext, id byte) *DynamicProfile
	ValidateProfile(ectx *EngineContext, p *DynamicProfile) error
}

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

type VaultManager interface {
	VaultGet(ectx *EngineContext, vaultPath string, service string, passphrase []byte, pin string) (*VaultEntry, error)
	VaultSet(ectx *EngineContext, vaultPath string, entry *VaultEntry, passphrase []byte, pin string) error
	VaultRename(ectx *EngineContext, oldName, newName string) error
	VaultDelete(ectx *EngineContext, name string) error
	VaultList(ectx *EngineContext, vaultPath string) ([]string, error)
	VaultSplit(ectx *EngineContext, vaultPath string, threshold, shares int, passphrase string) ([]string, error)
	VaultRecover(ectx *EngineContext, mnemonics []string, vaultPath string, output string, passphrase string) (string, error)
}

type P2PService interface {
	P2PSend(ectx *EngineContext, inputName string, r io.Reader, opts P2PSendOptions) (string, <-chan P2PStatus, error)
	P2PReceive(ectx *EngineContext, code string, opts P2PReceiveOptions) (<-chan P2PStatus, error)
	ValidateWormholeURL(ectx *EngineContext, urlStr string) error
}

type Utils interface {
	GeneratePassword(ectx *EngineContext, length int, noSymbols bool) (string, error)
	GeneratePassphrase(ectx *EngineContext, words int, separator string) (string, error)
}

type StateProvider interface {
	GetPolicy() SecurityPolicy
	GetConfig() *Config
	UpdateConfig(ectx *EngineContext, newConf *Config) error
	RegisterProfile(ectx *EngineContext, name string, dp *DynamicProfile) error
	RemoveProfile(ectx *EngineContext, name string) error
}

type TunnelService interface {
	TunnelStart(ectx *EngineContext, opts tunnel.TunnelOptions) (tunnel.TunnelStatus, error)
	TunnelListen(ectx *EngineContext, addr string, useWormhole bool) (string, <-chan tunnel.TunnelStatus, error)
	TunnelStop(ectx *EngineContext) error
	TunnelStatus(ectx *EngineContext) (tunnel.TunnelStatus, error)
}

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

type Inspector interface {
	Inspect(ectx *EngineContext, in io.Reader) (*HeaderInfo, error)
}

// Engine Implementation
type Engine struct {
	Policy     SecurityPolicy
	Config     *Config
	Identities *IdentityManager

	activeTunnel *tunnel.TunnelStatus
	mux          tunnel.TunnelMux
	gateway      *tunnel.TunnelGateway
	tunnelMu     sync.RWMutex
}

func NewEngine(policy SecurityPolicy) (*Engine, error) {
	conf, err := LoadConfig()
	if err != nil { return nil, err }
	return &Engine{
		Policy:     policy,
		Config:     conf,
		Identities: NewIdentityManager(),
	}, nil
}

func (e *Engine) GetPolicy() SecurityPolicy { return e.Policy }
func (e *Engine) GetConfig() *Config        { return e.Config }

func (e *Engine) UpdateConfig(ectx *EngineContext, newConf *Config) error {
	ectx = e.context(ectx)
	if !ectx.Policy.AllowConfigModification() { return &ErrPolicyViolation{Reason: "configuration modification prohibited"} }
	if err := newConf.Validate(); err != nil { return err }
	if err := newConf.Save(); err != nil { return err }
	e.Config = newConf
	return nil
}

func (e *Engine) RegisterProfile(ectx *EngineContext, name string, dp *DynamicProfile) error {
	ectx = e.context(ectx)
	if !ectx.Policy.AllowConfigModification() { return &ErrPolicyViolation{Reason: "profile registration prohibited"} }
	if e.Config.Profiles == nil { e.Config.Profiles = make(map[string]*DynamicProfile) }
	e.Config.Profiles[name] = dp
	RegisterProfile(dp)
	return e.Config.Save()
}

func (e *Engine) RemoveProfile(ectx *EngineContext, name string) error {
	ectx = e.context(ectx)
	if !ectx.Policy.AllowConfigModification() { return &ErrPolicyViolation{Reason: "profile removal prohibited"} }
	delete(e.Config.Profiles, name)
	return e.Config.Save()
}

func (e *Engine) Inspect(_ *EngineContext, in io.Reader) (*HeaderInfo, error) {
	magic, profile, flags, recipients, err := ReadHeader(in, false)
	if err != nil { return nil, err }
	return &HeaderInfo{
		Magic: magic, ProfileID: profile, Flags: flags, RecipientCount: recipients,
		IsCompressed: flags&FlagCompress != 0, IsArchive: flags&FlagArchive != 0,
		IsSigned: flags&FlagSigned != 0, IsStealth: flags&FlagStealth != 0,
	}, nil
}

func (e *Engine) TunnelStart(ectx *EngineContext, opts tunnel.TunnelOptions) (tunnel.TunnelStatus, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapP2P); err != nil { return tunnel.TunnelStatus{}, err }
	e.tunnelMu.Lock()
	defer e.tunnelMu.Unlock()
	if e.activeTunnel != nil && e.activeTunnel.Active { return *e.activeTunnel, fmt.Errorf("tunnel already active") }

	var mux tunnel.TunnelMux
	var err error
	var remoteEndpoint = opts.RemoteEndpoint

	if opts.WormholeCode != "" {
		slog.Info("tunnel: establishing Magic Wormhole transit stream", "code", opts.WormholeCode)
		stream, err := tunnel.EstablishGhostStream(ectx.Context, e.Config.Wormhole.RendezvousURL, opts.WormholeCode, false)
		if err != nil { return tunnel.TunnelStatus{}, err }
		
		pconn := &tunnel.WormholePacketConn{Stream: stream}
		tlsConf := tunnel.GetPQCConfig()
		tlsConf.InsecureSkipVerify = true
		mux, err = tunnel.DialWithConn(ectx.Context, pconn, "ghost", tlsConf, e.Config.Tunnel)
		if err != nil { return tunnel.TunnelStatus{}, err }
	} else {
		tlsConf := tunnel.GetPQCConfig()
		tlsConf.InsecureSkipVerify = true
		mux, err = tunnel.Dial(ectx.Context, remoteEndpoint, tlsConf, e.Config.Tunnel)
		if err != nil { return tunnel.TunnelStatus{}, err }
	}

	gw := &tunnel.TunnelGateway{Port: opts.LocalProxyPort, Mux: mux}
	if err := gw.Start(); err != nil { mux.Close(); return tunnel.TunnelStatus{}, err }

	e.activeTunnel = &tunnel.TunnelStatus{
		Active: true, LocalAddress: fmt.Sprintf("127.0.0.1:%d", opts.LocalProxyPort),
		RemoteEndpoint: remoteEndpoint, HandshakeTime: time.Now().Format(time.RFC3339),
	}
	e.mux = mux; e.gateway = gw
	return *e.activeTunnel, nil
}

func (e *Engine) TunnelListen(ectx *EngineContext, addr string, useWormhole bool) (string, <-chan tunnel.TunnelStatus, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapP2P); err != nil { return "", nil, err }
	statusCh := make(chan tunnel.TunnelStatus, 5)

	if !useWormhole {
		tlsConf := tunnel.GetPQCConfig()
		cert, err := tunnel.GenerateTestCertificate()
		if err != nil { return "", nil, err }
		tlsConf.Certificates = []tls.Certificate{cert}
		ln, err := tunnel.Listen(addr, tlsConf, e.Config.Tunnel)
		if err != nil { return "", nil, err }

		go func() {
			defer close(statusCh)
			mux, err := ln.Accept(ectx.Context)
			if err != nil { return }
			statusCh <- tunnel.TunnelStatus{Active: true, LocalAddress: addr}
			server := &tunnel.TunnelServer{Mux: mux}
			server.Start(ectx.Context)
		}()
		return "", statusCh, nil
	}

	// REAL GHOST MODE: Coordinated QUIC-over-Wormhole
	c := wormhole.Client{RendezvousURL: e.Config.Wormhole.RendezvousURL}
	pr, pw := io.Pipe()
	code, status, err := c.SendFile(ectx.Context, "ghost-tunnel", &pipeSeeker{pr})
	if err != nil { return "", nil, err }

	go func() {
		defer close(statusCh)
		defer pw.Close()
		for range status {}

		pconn := &tunnel.WormholePacketConn{Stream: &tunnelTransitBridge{Reader: pr, Writer: pw}}
		tlsConf := tunnel.GetPQCConfig()
		cert, _ := tunnel.GenerateTestCertificate()
		tlsConf.Certificates = []tls.Certificate{cert}
		
		ln, err := tunnel.ListenWithConn(pconn, "ghost", tlsConf, e.Config.Tunnel)
		if err != nil { return }
		
		mux, err := ln.Accept(ectx.Context)
		if err != nil { return }
		
		statusCh <- tunnel.TunnelStatus{Active: true, LocalAddress: "wormhole"}
		server := &tunnel.TunnelServer{Mux: mux}
		server.Start(ectx.Context)
	}()

	return code, statusCh, nil
}

type tunnelTransitBridge struct {
	io.Reader
	io.Writer
}
func (b *tunnelTransitBridge) Close() error { return nil }

func (e *Engine) TunnelStop(ectx *EngineContext) error {
	e.tunnelMu.Lock()
	defer e.tunnelMu.Unlock()
	if e.gateway != nil { e.gateway.Stop() }
	if e.mux != nil { e.mux.Close() }
	e.activeTunnel = nil; e.mux = nil; e.gateway = nil
	return nil
}

func (e *Engine) TunnelStatus(ectx *EngineContext) (tunnel.TunnelStatus, error) {
	e.tunnelMu.RLock(); defer e.tunnelMu.RUnlock()
	if e.activeTunnel == nil { return tunnel.TunnelStatus{Active: false}, nil }
	return *e.activeTunnel, nil
}

func (e *Engine) context(ectx *EngineContext) *EngineContext {
	if ectx == nil { return &EngineContext{Context: context.Background(), Policy: e.Policy} }
	if ectx.Policy == nil { ectx.Policy = e.Policy }
	if ectx.Context == nil { ectx.Context = context.Background() }
	return ectx
}

func (e *Engine) enforce(ectx *EngineContext, cap Capability) error {
	ectx = e.context(ectx)
	if !ectx.Policy.HasCapability(cap) { return &ErrPolicyViolation{Reason: fmt.Sprintf("prohibited capability: %s", cap)} }
	return nil
}

func (e *Engine) ValidateWormholeURL(ectx *EngineContext, urlStr string) error {
	ectx = e.context(ectx)
	return ectx.Policy.ValidateWormholeURL(urlStr, e.Config.AgentLimits.AllowedURLs)
}

func (e *Engine) GeneratePassword(ectx *EngineContext, length int, noSymbols bool) (string, error) { return GeneratePassword(length, noSymbols) }
func (e *Engine) GeneratePassphrase(ectx *EngineContext, words int, separator string) (string, error) { return GeneratePassphrase(words, separator) }

var bufferPool = sync.Pool{
	New: func() any { b := make([]byte, ChunkSize+256); return &b },
}

func SafeClear(b []byte) {
	if b == nil { return }
	for i := range b { b[i] = 0 }
}

type pipeSeeker struct{ io.Reader }
func (p *pipeSeeker) Seek(offset int64, whence int) (int64, error) { return 0, nil }
