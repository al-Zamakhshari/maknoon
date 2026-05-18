package crypto

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/libp2p/go-libp2p"
	"github.com/multiformats/go-multiaddr"
)

// --- Engine Wrappers ---

func (e *Engine) TunnelStart(ectx *EngineContext, opts tunnel.TunnelOptions) (tunnel.TunnelStatus, error) {
	return e.Network.TunnelStart(ectx, opts)
}

func (e *Engine) TunnelStop(ectx *EngineContext) error {
	return e.Network.TunnelStop(ectx)
}

func (e *Engine) TunnelStatus(ectx *EngineContext) (tunnel.TunnelStatus, error) {
	return e.Network.TunnelStatus(ectx)
}

func (e *Engine) TunnelListen(ectx *EngineContext, addr, mode, identity string) (NetworkResult, error) {
	return e.Network.TunnelListen(ectx, addr, mode, identity)
}

func (e *Engine) P2PSend(ectx *EngineContext, identityName, inputName string, r io.Reader, opts P2PSendOptions) (string, <-chan P2PStatus, error) {
	return e.Network.P2PSend(ectx, identityName, inputName, r, opts)
}

func (e *Engine) P2PReceive(ectx *EngineContext, identityName, code string, opts P2PReceiveOptions) (<-chan P2PStatus, error) {
	return e.Network.P2PReceive(ectx, identityName, code, opts)
}

func (e *Engine) ChatStart(ectx *EngineContext, identityName, target string) (*P2PChatSession, error) {
	return e.Network.ChatStart(ectx, identityName, target)
}

func (e *Engine) ValidateWormholeURL(ectx *EngineContext, u string) error {
	return e.Network.ValidateWormholeURL(ectx, u)
}

// --- NetworkService Implementation ---

func (s *NetworkService) TunnelStart(ectx *EngineContext, opts tunnel.TunnelOptions) (tunnel.TunnelStatus, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapP2P); err != nil {
		return tunnel.TunnelStatus{}, err
	}

	// Governance: Validate tunnel security standards
	if err := ectx.Policy.ValidateTunnel(opts.Insecure); err != nil {
		return tunnel.TunnelStatus{}, err
	}

	s.tunnelMu.Lock()
	defer s.tunnelMu.Unlock()

	if s.activeTunnel != nil && s.activeTunnel.Active {
		return *s.activeTunnel, fmt.Errorf("a tunnel is already active")
	}

	targetAddr := opts.P2PAddr
	if targetAddr == "" {
		targetAddr = opts.RemoteEndpoint
	}

	if opts.P2PMode && targetAddr != "" {
		if strings.HasPrefix(targetAddr, "@") {
			reg := NewIdentityRegistry(s.engine.Config)
			record, err := reg.Resolve(ectx.Context, targetAddr)
			if err != nil {
				return tunnel.TunnelStatus{}, fmt.Errorf("failed to resolve tunnel peer '%s': %w", targetAddr, err)
			}
			if len(record.Multiaddrs) == 0 {
				return tunnel.TunnelStatus{}, fmt.Errorf("resolved peer '%s' has no active multiaddrs", targetAddr)
			}
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
			opts.P2PAddr = bestAddr
		} else {
			// Direct multiaddr
			opts.P2PAddr = targetAddr
		}
	}

	var libp2pOpts []libp2p.Option
	if opts.P2PMode && opts.Identity != "" {
		id, err := s.engine.Identity.LoadIdentity(ectx, opts.Identity, nil, "", false)
		if err != nil {
			return tunnel.TunnelStatus{}, err
		}
		priv, err := id.AsLibp2pKey()
		if err != nil {
			return tunnel.TunnelStatus{}, err
		}
		libp2pOpts = append(libp2pOpts, libp2p.Identity(priv))
	}

	factory := &tunnel.TransportFactory{Config: s.engine.Config.Tunnel}
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
		remote = "libp2p-resilient-tunnel"
	}

	status := tunnel.TunnelStatus{
		Active:         true,
		LocalAddress:   fmt.Sprintf("127.0.0.1:%d", opts.LocalProxyPort),
		RemoteEndpoint: remote,
		HandshakeTime:  time.Now().Format(time.RFC3339),
		DataLanes:      opts.DataLanes,
		ParityLanes:    opts.ParityLanes,
	}
	if opts.DataLanes > 0 {
		status.HealthyLanes = opts.DataLanes + opts.ParityLanes
	}

	s.activeTunnel = &status
	s.gateway = gw

	return status, nil
}

func (s *NetworkService) TunnelStop(ectx *EngineContext) error {
	s.tunnelMu.Lock()
	defer s.tunnelMu.Unlock()

	if s.activeTunnel == nil {
		return nil
	}

	if s.gateway != nil {
		s.gateway.Stop()
	}

	s.activeTunnel = nil
	s.gateway = nil

	if s.gatewayServer != nil {
		s.gatewayServer.Stop()
		s.gatewayServer = nil
	}

	return nil
}

func (s *NetworkService) TunnelStatus(ectx *EngineContext) (tunnel.TunnelStatus, error) {
	s.tunnelMu.RLock()
	defer s.tunnelMu.RUnlock()

	if s.activeTunnel == nil {
		return tunnel.TunnelStatus{Active: false}, nil
	}

	return *s.activeTunnel, nil
}

func (s *NetworkService) TunnelListen(ectx *EngineContext, addr, mode, identity string) (NetworkResult, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapP2P); err != nil {
		return NetworkResult{}, err
	}

	var libp2pOpts []libp2p.Option
	if mode == "p2p" {
		if addr != "" {
			port := strings.TrimPrefix(addr, ":")
			ma, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", port))
			if err == nil {
				libp2pOpts = append(libp2pOpts, libp2p.ListenAddrs(ma))
			}
		}
		if identity != "" {
			id, err := s.engine.Identity.LoadIdentity(ectx, identity, nil, "", false)
			if err != nil {
				return NetworkResult{}, err
			}
			priv, err := id.AsLibp2pKey()
			if err != nil {
				return NetworkResult{}, err
			}
			libp2pOpts = append(libp2pOpts, libp2p.Identity(priv))
		}

		h, err := tunnel.NewLibp2pHost(libp2pOpts...)
		if err != nil {
			return NetworkResult{}, err
		}
		s.engine.RegisterQuorumHandler(h)
		ln := tunnel.StartLibp2pListener(h)
		srv := tunnel.NewTunnelServer(ln)

		s.tunnelMu.Lock()
		s.gatewayServer = srv
		s.tunnelMu.Unlock()

		go srv.Start()

		res := NetworkResult{
			Status: "listening",
			PeerID: h.ID().String(),
		}
		var canonical string
		for _, a := range h.Addrs() {
			ma := fmt.Sprintf("%s/p2p/%s", a, h.ID())
			res.Addrs = append(res.Addrs, ma)
			if canonical == "" && strings.Contains(ma, "/127.0.0.1/") && strings.Contains(ma, "/tcp/") {
				canonical = ma
			}
		}
		if canonical == "" && len(res.Addrs) > 0 {
			canonical = res.Addrs[0]
		}
		res.CanonicalAddr = canonical
		return res, nil
	}

	factory := &tunnel.TransportFactory{Config: s.engine.Config.Tunnel}
	ln, err := factory.CreateListener(ectx.Context, addr, mode)
	if err != nil {
		return NetworkResult{}, err
	}
	srv := tunnel.NewTunnelServer(ln)

	s.tunnelMu.Lock()
	s.gatewayServer = srv
	s.tunnelMu.Unlock()

	go srv.Start()

	return NetworkResult{Status: "listening", Addrs: []string{ln.Addr().String()}}, nil
}

func (s *NetworkService) P2PSend(ectx *EngineContext, identityName, inputName string, r io.Reader, opts P2PSendOptions) (string, <-chan P2PStatus, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapP2P); err != nil {
		return "", nil, err
	}
	if opts.TraceID == "" {
		opts.TraceID = GenerateTraceID()
	}
	s.engine.Logger.Debug("P2PSend initiating", "trace_id", opts.TraceID, "input", inputName, "target", opts.To)

	idName := identityName
	if idName == "" {
		idName = s.engine.GetConfig().DefaultIdentity
	}
	if idName == "" {
		idName = "default"
	}

	id, err := s.engine.Identity.Mgr.LoadIdentity(idName, opts.Passphrase, "", false)
	if err != nil {
		return "", nil, err
	}
	priv, err := id.AsLibp2pKey()
	if err != nil {
		return "", nil, err
	}
	h, err := tunnel.NewLibp2pHost(libp2p.Identity(priv))
	if err != nil {
		return "", nil, err
	}

	status := make(chan P2PStatus, 10)
	if opts.DataShards > 0 {
		go s.engine.runLibp2pFragmentSend(ectx, inputName, r, h, opts.To, opts, status)
	} else {
		go s.engine.runLibp2pSend(ectx, inputName, r, h, opts.To, opts, status)
	}
	return h.ID().String(), status, nil
}

func (s *NetworkService) P2PReceive(ectx *EngineContext, identityName, code string, opts P2PReceiveOptions) (<-chan P2PStatus, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapP2P); err != nil {
		return nil, err
	}
	if opts.TraceID == "" {
		opts.TraceID = GenerateTraceID()
	}
	s.engine.Logger.Debug("P2PReceive initiating", "trace_id", opts.TraceID, "identity", identityName)

	idName := identityName
	if idName == "" {
		idName = s.engine.GetConfig().DefaultIdentity
	}
	if idName == "" {
		idName = "default"
	}

	id, err := s.engine.Identity.Mgr.LoadIdentity(idName, opts.Passphrase, "", false)
	if err != nil {
		return nil, err
	}
	if len(opts.PrivateKey) == 0 {
		opts.PrivateKey = id.KEMPriv
	}
	priv, err := id.AsLibp2pKey()
	if err != nil {
		return nil, err
	}
	h, err := tunnel.NewLibp2pHost(libp2p.Identity(priv))
	if err != nil {
		return nil, err
	}
	s.engine.RegisterQuorumHandler(h)

	storageDir := opts.OutputDir
	if storageDir == "" {
		storageDir = "."
	}
	s.engine.RegisterFragmentHandler(h, storageDir)

	status := make(chan P2PStatus, 10)
	if opts.IsFragmented {
		go s.engine.runLibp2pFragmentReceive(ectx, code, h, opts, status)
	} else {
		go s.engine.runLibp2pReceive(ectx, h, opts, status)
	}

	var addrs []string
	for _, a := range h.Addrs() {
		addrs = append(addrs, a.String()+"/p2p/"+h.ID().String())
	}
	status <- P2PStatus{Phase: "connecting", Code: h.ID().String(), Addrs: addrs}
	return status, nil
}

func (s *NetworkService) ChatStart(ectx *EngineContext, identityName, target string) (*P2PChatSession, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapP2P); err != nil {
		return nil, err
	}

	idName := identityName
	if idName == "" {
		idName = s.engine.GetConfig().DefaultIdentity
	}
	if idName == "" {
		idName = "default"
	}

	id, err := s.engine.Identity.Mgr.LoadIdentity(idName, nil, "", false)
	if err != nil {
		return nil, err
	}
	priv, err := id.AsLibp2pKey()
	if err != nil {
		return nil, err
	}
	h, err := tunnel.NewLibp2pHost(libp2p.Identity(priv))
	if err != nil {
		return nil, err
	}

	sess := NewP2PChatSession(h)
	if target == "" {
		if _, err = sess.StartHost(ectx.Context); err != nil {
			h.Close()
			return nil, err
		}
	} else {
		if strings.HasPrefix(target, "@") {
			if err := s.engine.ensureContacts(); err != nil {
				return nil, err
			}
			c, err := s.engine.Contacts.Get(target)
			if err != nil {
				return nil, err
			}
			target = c.PeerID
		}
		if err = sess.StartJoin(ectx.Context, target); err != nil {
			h.Close()
			return nil, err
		}
	}

	return sess, nil
}

func (s *NetworkService) ValidateWormholeURL(ectx *EngineContext, u string) error {
	return nil // Deprecated
}

// networkMultiaddrsAdapter implements MultiaddrsProvider using NetworkService.
// It is a thin adapter that breaks the circular Engine→IdentityManager→Engine reference
// by exposing only the narrow Multiaddrs capability needed by IdentityPublish.
type networkMultiaddrsAdapter struct {
	network *NetworkService
}

// Multiaddrs starts a transient libp2p host for identityName, waits briefly for
// address detection, then returns the discovered multiaddrs and closes the session.
func (a *networkMultiaddrsAdapter) Multiaddrs(ctx context.Context, identityName string) []string {
	sess, err := a.network.ChatStart(nil, identityName, "")
	if err != nil {
		return nil
	}
	time.Sleep(2 * time.Second)
	addrs := sess.Multiaddrs()
	sess.Close()
	return addrs
}
