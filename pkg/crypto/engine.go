package crypto

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/awnumar/memguard"
	"github.com/libp2p/go-libp2p"
	"github.com/multiformats/go-multiaddr"
)

// Engine is the central stateful service for Maknoon operations.
type Engine struct {
	Policy     SecurityPolicy
	Config     *Config
	Identities *IdentityManager
	Vaults     VaultStore
	Contacts   *ContactManager
	Logger     *slog.Logger

	// Contacts State
	contactsMu   sync.Mutex
	contactsPath string

	// Tunnel State
	activeTunnel  *tunnel.TunnelStatus
	gateway       *tunnel.TunnelGateway
	gatewayServer *tunnel.TunnelServer
	tunnelMu      sync.RWMutex
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

func (e *Engine) Inspect(_ *EngineContext, in io.Reader, stealth bool) (*HeaderInfo, error) {
	// We need to peek/read the header. ReadHeader does this.
	// However, ReadHeader might consume too much if it's not a seekable reader.
	// Since engine.Inspect is called with a reader, we assume it's the start of the stream.
	magic, profileID, flags, recipients, err := ReadHeader(in, stealth)
	if err != nil {
		return nil, err
	}

	info := &HeaderInfo{
		Magic:          magic,
		ProfileID:      profileID,
		Flags:          flags,
		RecipientCount: recipients,
		Compressed:     flags&FlagCompress != 0,
		IsArchive:      flags&FlagArchive != 0,
		IsSigned:       flags&FlagSigned != 0,
		IsStealth:      stealth || flags&FlagStealth != 0,
	}

	if magic == MagicHeader {
		info.Type = "symmetric"
	} else if magic == MagicHeaderAsym {
		info.Type = "asymmetric"
	}

	if info.IsStealth {
		info.Type = "stealth"
	}

	// Try to get profile details
	profile, err := GetProfile(profileID, nil)
	if err == nil {
		info.KEMAlgorithm = profile.KEMName()
		info.SIGAlgorithm = profile.SIGName()

		if v1, ok := profile.(*ProfileV1); ok {
			info.KDFDetails = fmt.Sprintf("Argon2id (t=%d, m=%d, p=%d)", v1.ArgonTime, v1.ArgonMem, v1.ArgonThrd)
		}
	}

	return info, nil
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

	// 0. Handle Petname Resolution for P2P addresses
	targetAddr := opts.P2PAddr
	if targetAddr == "" && strings.HasPrefix(opts.RemoteEndpoint, "@") {
		targetAddr = opts.RemoteEndpoint
	}

	if opts.P2PMode && strings.HasPrefix(targetAddr, "@") {
		reg := NewIdentityRegistry(e.Config)
		record, err := reg.Resolve(ectx.Context, targetAddr)
		if err != nil {
			return tunnel.TunnelStatus{}, fmt.Errorf("failed to resolve tunnel peer '%s': %w", targetAddr, err)
		}
		if len(record.Multiaddrs) == 0 {
			return tunnel.TunnelStatus{}, fmt.Errorf("resolved peer '%s' has no active multiaddrs", targetAddr)
		}
		// Prefer non-loopback addresses
		var bestAddr string
		for _, ma := range record.Multiaddrs {
			if ma == "" {
				continue
			}
			if !strings.Contains(ma, "/127.0.0.1/") && !strings.Contains(ma, "/::1/") {
				bestAddr = ma
				break
			}
		}
		if bestAddr == "" && len(record.Multiaddrs) > 0 {
			bestAddr = record.Multiaddrs[0]
		}

		if bestAddr == "" {
			return tunnel.TunnelStatus{}, fmt.Errorf("failed to resolve a valid multiaddr for '%s' (found %d addrs)", targetAddr, len(record.Multiaddrs))
		}

		e.Logger.Info("p2p resolution complete",
			"handle", targetAddr,
			"multiaddr", bestAddr,
			"addr_count", len(record.Multiaddrs))
		opts.P2PAddr = bestAddr
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
		BindAddr: opts.BindAddr,
		Port:     opts.LocalProxyPort,
		Session:  session,
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

func (e *Engine) TunnelListen(ectx *EngineContext, addr string, mode string, identity string) (NetworkResult, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapP2P); err != nil {
		return NetworkResult{}, err
	}

	var libp2pOpts []libp2p.Option
	if mode == "p2p" {
		if addr != "" {
			// Try to parse as port (e.g. :4001)
			port := strings.TrimPrefix(addr, ":")
			ma, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", port))
			if err == nil {
				libp2pOpts = append(libp2pOpts, libp2p.ListenAddrs(ma))
			}
		}
	}

	if mode == "p2p" && identity != "" {
		id, err := e.Identities.LoadIdentity(identity, nil, "", false)
		if err != nil {
			return NetworkResult{}, err
		}
		priv, err := id.AsLibp2pKey()
		if err != nil {
			return NetworkResult{}, err
		}
		libp2pOpts = append(libp2pOpts, libp2p.Identity(priv))
	}

	if mode == "p2p" {
		h, err := tunnel.NewLibp2pHost(libp2pOpts...)
		if err != nil {
			return NetworkResult{}, err
		}
		ln := tunnel.StartLibp2pListener(h)
		e.gatewayServer = tunnel.NewTunnelServer(ln)
		go e.gatewayServer.Start()

		res := NetworkResult{
			Status: "listening",
			PeerID: h.ID().String(),
		}
		for _, a := range h.Addrs() {
			res.Addrs = append(res.Addrs, fmt.Sprintf("%s/p2p/%s", a, h.ID()))
		}
		e.Logger.Info("P2P Tunnel Server active", "peer_id", res.PeerID, "addrs", res.Addrs)
		return res, nil
	}

	// Standard (Non-P2P) listener logic
	factory := &tunnel.TransportFactory{Config: e.Config.Tunnel}
	ln, err := factory.CreateListener(ectx.Context, addr, mode)
	if err != nil {
		return NetworkResult{}, err
	}

	e.gatewayServer = tunnel.NewTunnelServer(ln)
	go e.gatewayServer.Start()

	e.Logger.Info("Tunnel Server active", "mode", mode, "addr", addr)
	return NetworkResult{Status: "listening", Addrs: []string{addr}}, nil
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
			c, err := e.Contacts.Get(target)
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

func (e *Engine) Close() error {
	if e.Contacts != nil {
		return e.Contacts.Close()
	}
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
	idMgr.Config = conf

	if vaultStore == nil {
		vaultStore = &FileSystemVaultStore{
			BaseDir: conf.Paths.VaultsDir,
			Backend: conf.VaultBackend,
		}
	}

	if logger == nil {
		logger = slog.Default()
	}

	e := &Engine{
		Policy:       policy,
		Config:       conf,
		Identities:   idMgr,
		Vaults:       vaultStore,
		Logger:       logger,
		contactsPath: filepath.Join(conf.Paths.VaultsDir, "..", "contacts.db"),
	}

	e.Identities.P2P = e // Inject P2P back-reference
	return e, nil
}

func (e *Engine) ensureContacts() error {
	e.contactsMu.Lock()
	defer e.contactsMu.Unlock()

	if e.Contacts != nil {
		return nil
	}

	store, err := e.Vaults.Open(e.contactsPath)
	if err != nil {
		return fmt.Errorf("failed to open contacts store: %w", err)
	}

	e.Contacts = NewContactManager(store)
	if e.Identities != nil {
		e.Identities.Contacts = e.Contacts
	}

	return nil
}

func (e *Engine) ContactAdd(ectx *EngineContext, petname, kemPub, sigPub, note string) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return err
	}

	if err := e.ensureContacts(); err != nil {
		return err
	}

	kemBytes, err := hex.DecodeString(kemPub)
	if err != nil {
		return fmt.Errorf("invalid KEM public key: %w", err)
	}
	sigBytes, err := hex.DecodeString(sigPub)
	if err != nil {
		return fmt.Errorf("invalid SIG public key: %w", err)
	}

	peerID, err := DerivePeerID(sigBytes)
	if err != nil {
		return err
	}

	contact := &Contact{
		Petname:   petname,
		KEMPubKey: kemBytes,
		SIGPubKey: sigBytes,
		PeerID:    peerID,
		AddedAt:   time.Now(),
		Notes:     note,
	}

	return e.Contacts.Add(contact)
}

func (e *Engine) ContactList(ectx *EngineContext) ([]*Contact, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	if err := e.ensureContacts(); err != nil {
		return nil, err
	}
	return e.Contacts.List()
}

func (e *Engine) ContactDelete(ectx *EngineContext, petname string) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return err
	}
	if err := e.ensureContacts(); err != nil {
		return err
	}
	return e.Contacts.Delete(petname)
}

func (e *Engine) ResolvePublicKey(ectx *EngineContext, input string, tofu bool) ([]byte, error) {
	ectx = e.context(ectx)
	// Resolution is usually a read operation, CapIdentity is sufficient
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}

	// Only ensure contacts if input is a petname (@handle)
	if strings.HasPrefix(input, "@") {
		if err := e.ensureContacts(); err != nil {
			return nil, err
		}
	}

	return e.Identities.ResolvePublicKey(input, tofu)
}

func (e *Engine) LoadPrivateKey(ectx *EngineContext, path string, passphrase []byte, pin string, agent bool) ([]byte, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return e.Identities.LoadPrivateKey(path, passphrase, pin, agent)
}

func (e *Engine) ResolveKeyPath(ectx *EngineContext, path, envVar string) string {
	return e.Identities.ResolveKeyPath(path, envVar)
}

func (e *Engine) ResolveBaseKeyPath(ectx *EngineContext, name string) (string, string, error) {
	return e.Identities.ResolveBaseKeyPath(name)
}

func (e *Engine) GeneratePassword(ectx *EngineContext, length int, noSymbols bool) (string, error) {
	return GeneratePassword(length, noSymbols)
}

func (e *Engine) GeneratePassphrase(ectx *EngineContext, words int, separator string) (string, error) {
	return GeneratePassphrase(words, separator)
}

func (e *Engine) Sign(ectx *EngineContext, data []byte, privKey []byte) ([]byte, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapCrypto); err != nil {
		return nil, err
	}
	return SignData(data, privKey)
}

func (e *Engine) Verify(ectx *EngineContext, data []byte, sig []byte, pubKey []byte) (bool, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapCrypto); err != nil {
		return false, err
	}
	return VerifySignature(data, sig, pubKey), nil
}

func (e *Engine) Wrap(ectx *EngineContext, pubKey []byte) (DataKey, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapCrypto); err != nil {
		return DataKey{}, err
	}

	// Generate a high-entropy 32-byte Data Encryption Key (DEK)
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return DataKey{}, err
	}
	defer SafeClear(dek)

	// Create a copy of the plaintext for the result BEFORE it's wiped by memguard
	plaintext := make([]byte, len(dek))
	copy(plaintext, dek)

	// Encapsulate the DEK using the provided public key (ML-KEM-768 hybrid)
	// memguard.NewEnclave takes ownership of dek and wipes it.
	profile := DefaultProfile()
	dekEnclave := memguard.NewEnclave(dek)
	wrapped, err := profile.WrapFEK(pubKey, 0, dekEnclave)
	if err != nil {
		return DataKey{}, err
	}

	return DataKey{
		Plaintext: plaintext,
		Wrapped:   wrapped,
	}, nil
}

func (e *Engine) Unwrap(ectx *EngineContext, wrappedKey []byte, privKey []byte) ([]byte, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapCrypto); err != nil {
		return nil, err
	}

	profile := DefaultProfile()
	dekEnclave, err := profile.UnwrapFEK(privKey, 0, wrappedKey)
	if err != nil {
		return nil, err
	}

	// Decapsulate and reveal the DEK
	lb, err := dekEnclave.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open DEK enclave: %w", err)
	}
	defer lb.Destroy()

	// Return a copy of the plaintext bytes
	plaintext := make([]byte, lb.Size())
	copy(plaintext, lb.Bytes())

	return plaintext, nil
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

// AuditExport returns a forensic history of cryptographic operations.
func (e *Engine) AuditExport(ectx *EngineContext) ([]AuditEntry, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapAudit); err != nil {
		return nil, err
	}

	logPath := e.Config.Audit.LogFile
	if logPath == "" {
		home := GetUserHomeDir()
		logPath = filepath.Join(home, MaknoonDir, "audit.log")
	}

	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEntry{}, nil
		}
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	defer f.Close()

	var entries []AuditEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
			entries = append(entries, entry)
		}
	}

	return entries, scanner.Err()
}

// NetworkStatus returns a snapshot of the P2P network and tunnel state.
func (e *Engine) NetworkStatus(ectx *EngineContext) (NetStatusResult, error) {
	res := NetStatusResult{}

	// 1. Check active tunnel
	e.tunnelMu.RLock()
	if e.activeTunnel != nil {
		res.Tunnel.Active = true
		res.Tunnel.LocalAddress = e.activeTunnel.LocalAddress
		res.Tunnel.RemoteEndpoint = e.activeTunnel.RemoteEndpoint
		res.Tunnel.HandshakeTime = e.activeTunnel.HandshakeTime
	}
	e.tunnelMu.RUnlock()

	// 2. Create a temporary host to check P2P environment (if no persistent host)
	h, err := tunnel.NewLibp2pHost()
	if err != nil {
		return res, fmt.Errorf("failed to initialize diagnostic host: %w", err)
	}
	defer h.Close()

	res.PeerID = h.ID().String()
	for _, addr := range h.Addrs() {
		res.Addresses = append(res.Addresses, addr.String())
	}
	for _, p := range h.Mux().Protocols() {
		res.Protocols = append(res.Protocols, string(p))
	}

	return res, nil
}

// Diagnostic gathers a complete manifest of the engine and environment state.
func (e *Engine) Diagnostic() DiagnosticResult {
	res := DiagnosticResult{}
	res.Timestamp = time.Now().Format(time.RFC3339)

	// System Info
	res.System.OS = runtime.GOOS
	res.System.Arch = runtime.GOARCH
	res.System.Go = runtime.Version()
	res.System.Version = "v1.3.x" // TODO: Wire to a central version constant

	// User Info
	if u, err := user.Current(); err == nil {
		res.User.UID = u.Uid
		res.User.GID = u.Gid
		res.User.Username = u.Username
		res.User.Home = u.HomeDir
	} else {
		res.User.Home = GetUserHomeDir()
	}

	// Path Info
	home := res.User.Home
	res.Paths.MaknoonDir = filepath.Join(home, MaknoonDir)
	res.Paths.Config = filepath.Join(home, MaknoonDir, ConfigFileName)
	res.Paths.Keys = filepath.Join(home, MaknoonDir, KeysDir)
	res.Paths.Vaults = filepath.Join(home, MaknoonDir, VaultsDir)

	// Engine Info
	res.Engine.Policy = e.Policy.Name()
	res.Engine.AgentMode = e.Policy.IsAgent()
	res.Engine.DefaultProfile = e.Config.Performance.DefaultProfile
	if profile, err := GetProfile(res.Engine.DefaultProfile, nil); err == nil {
		res.Engine.ProfileName = profile.Name()
	}
	res.Engine.AuditEnabled = e.Config.Audit.Enabled

	res.Performance = e.Config.Performance

	return res
}
