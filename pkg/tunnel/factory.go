package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/libp2p/go-libp2p"
	"github.com/multiformats/go-multiaddr"
)

// TransportFactory orchestrates the creation of polymorphic L4 transports.
type TransportFactory struct {
	Config TunnelConfig
}

// CreateClientSession instantiates a MuxSession based on the provided options.
func (f *TransportFactory) CreateClientSession(ctx context.Context, opts TunnelOptions, extraOpts ...libp2p.Option) (MuxSession, error) {
	createSingle := func() (MuxSession, error) {
		if opts.P2PMode {
			h, err := NewLibp2pHost(extraOpts...)
			if err != nil {
				return nil, fmt.Errorf("failed to start libp2p host: %w", err)
			}
			return DialLibp2p(ctx, h, opts.P2PAddr)
		}

		if opts.UseYamux {
			tlsConf := GetPQCConfig()
			tlsConf.InsecureSkipVerify = opts.Insecure
			conn, err := tls.Dial("tcp", opts.RemoteEndpoint, tlsConf)
			if err != nil {
				return nil, fmt.Errorf("failed to connect via PQC-TCP: %w", err)
			}
			return WrapYamux(conn, false)
		}

		// Default: Direct PQC QUIC
		tlsConf := GetPQCConfig()
		tlsConf.InsecureSkipVerify = opts.Insecure
		return Dial(ctx, opts.RemoteEndpoint, tlsConf, f.Config)
	}

	if opts.DataLanes > 0 {
		total := opts.DataLanes + opts.ParityLanes
		subs := make([]MuxSession, total)
		for i := 0; i < total; i++ {
			s, err := createSingle()
			if err != nil {
				// Cleanup
				for j := 0; j < i; j++ {
					subs[j].Close()
				}
				return nil, fmt.Errorf("failed to create sub-session %d: %w", i, err)
			}
			subs[i] = s
		}
		return NewResilientMuxSession(subs, opts.DataLanes, opts.ParityLanes)
	}

	return createSingle()
}

// CreateListener instantiates a MuxListener based on the provided options.
func (f *TransportFactory) CreateListener(ctx context.Context, addr string, mode string) (MuxListener, error) {
	switch mode {
	case "p2p":
		var opts []libp2p.Option
		if addr != "" && addr != ":0" {
			ma, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", strings.TrimPrefix(addr, ":")))
			if err == nil {
				opts = append(opts, libp2p.ListenAddrs(ma))
			}
		}
		h, err := NewLibp2pHost(opts...)
		if err != nil {
			return nil, err
		}
		return StartLibp2pListener(h), nil

	case "yamux":
		tlsConf := GetPQCConfig()
		cert, err := GenerateTestCertificate()
		if err != nil {
			return nil, err
		}
		tlsConf.Certificates = []tls.Certificate{cert}
		l, err := tls.Listen("tcp", addr, tlsConf)
		if err != nil {
			return nil, err
		}
		return &TCPListener{Listener: l}, nil

	default:
		tlsConf := GetPQCConfig()
		cert, err := GenerateTestCertificate()
		if err != nil {
			return nil, err
		}
		tlsConf.Certificates = []tls.Certificate{cert}
		return Listen(addr, tlsConf, f.Config)
	}
}
