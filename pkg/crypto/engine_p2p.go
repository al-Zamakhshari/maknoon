package crypto

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/libp2p/go-libp2p"
	"github.com/multiformats/go-multiaddr"
)

func (e *Engine) TunnelStart(ectx *EngineContext, opts tunnel.TunnelOptions) (tunnel.TunnelStatus, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapP2P); err != nil {
		return tunnel.TunnelStatus{}, err
	}

	e.tunnelMu.Lock()
	defer e.tunnelMu.Unlock()

	if e.activeTunnel != nil {
		if at, ok := e.activeTunnel.(*tunnel.TunnelStatus); ok && at.Active {
			return *at, fmt.Errorf("a tunnel is already active")
		}
	}

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

	status := &tunnel.TunnelStatus{
		Active:         true,
		LocalAddress:   fmt.Sprintf("127.0.0.1:%d", opts.LocalProxyPort),
		RemoteEndpoint: remote,
		HandshakeTime:  time.Now().Format(time.RFC3339),
	}
	e.activeTunnel = status
	e.gateway = gw

	return *status, nil
}

func (e *Engine) TunnelStop(ectx *EngineContext) error {
	e.tunnelMu.Lock()
	defer e.tunnelMu.Unlock()

	if e.gateway != nil {
		if gw, ok := e.gateway.(*tunnel.TunnelGateway); ok {
			gw.Stop()
			if gw.Session != nil {
				gw.Session.Close()
			}
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
	if at, ok := e.activeTunnel.(*tunnel.TunnelStatus); ok {
		return *at, nil
	}
	return tunnel.TunnelStatus{Active: false}, nil
}

func (e *Engine) TunnelListen(ectx *EngineContext, addr string, mode string, identity string) (NetworkResult, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapP2P); err != nil {
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
		srv := tunnel.NewTunnelServer(ln)
		e.gatewayServer = srv
		go srv.Start()

		res := NetworkResult{
			Status: "listening",
			PeerID: h.ID().String(),
		}
		for _, a := range h.Addrs() {
			res.Addrs = append(res.Addrs, fmt.Sprintf("%s/p2p/%s", a, h.ID()))
		}
		return res, nil
	}

	factory := &tunnel.TransportFactory{Config: e.Config.Tunnel}
	ln, err := factory.CreateListener(ectx.Context, addr, mode)
	if err != nil {
		return NetworkResult{}, err
	}

	srv := tunnel.NewTunnelServer(ln)
	e.gatewayServer = srv
	go srv.Start()

	return NetworkResult{Status: "listening", Addrs: []string{addr}}, nil
}

func (e *Engine) ChatStart(ectx *EngineContext, identityName string, target string) (*P2PChatSession, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapP2P); err != nil {
		return nil, err
	}

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
		_, err = sess.StartHost(ectx.Context)
	} else {
		if strings.HasPrefix(target, "@") {
			if err := e.ensureContacts(); err != nil {
				return nil, err
			}
			c, err := e.Contacts.Get(target)
			if err != nil {
				return nil, err
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

	go func() {
		<-ectx.Context.Done()
		h.Close()
	}()

	return nil
}

func (e *Engine) P2PSend(ectx *EngineContext, identityName string, inputName string, r io.Reader, opts P2PSendOptions) (string, <-chan P2PStatus, error) {
	ectx = e.context(ectx)
	if opts.TraceID == "" {
		opts.TraceID = GenerateTraceID()
	}
	e.Logger.Debug("P2PSend initiating", "trace_id", opts.TraceID, "input", inputName, "target", opts.To)

	status := make(chan P2PStatus, 10)

	idName := identityName
	if idName == "" {
		idName = e.GetConfig().DefaultIdentity
	}
	if idName == "" {
		idName = "default"
	}

	id, err := e.Identities.LoadIdentity(idName, nil, "", false)
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
	go e.runLibp2pSend(ectx, inputName, r, h, opts.To, opts, status)
	return h.ID().String(), status, nil
}

func (e *Engine) P2PReceive(ectx *EngineContext, identityName string, code string, opts P2PReceiveOptions) (<-chan P2PStatus, error) {
	ectx = e.context(ectx)
	if opts.TraceID == "" {
		opts.TraceID = GenerateTraceID()
	}
	e.Logger.Debug("P2PReceive initiating", "trace_id", opts.TraceID, "identity", identityName)

	status := make(chan P2PStatus, 10)

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
	go e.runLibp2pReceive(ectx, h, opts, status)

	var addrs []string
	for _, a := range h.Addrs() {
		addrs = append(addrs, a.String()+"/p2p/"+h.ID().String())
	}

	status <- P2PStatus{Phase: "connecting", Code: h.ID().String(), Addrs: addrs}
	return status, nil
}

func (e *Engine) ValidateWormholeURL(ectx *EngineContext, url string) error {
	return nil // Deprecated
}
