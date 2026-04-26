package tunnel

import (
	"context"
	"fmt"
	"net"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/multiformats/go-multiaddr"
)

// MaknoonProtocol is the libp2p protocol ID for Maknoon L4 tunnels.
const MaknoonProtocol = "/maknoon/l4/1.0.0"

// Libp2pSession implements MuxSession for go-libp2p.
type Libp2pSession struct {
	Host         host.Host
	PeerID       peer.ID
	singleStream network.Stream // Used by server side
}

// OpenStream initiates a new multiplexed stream.
func (s *Libp2pSession) OpenStream(ctx context.Context) (net.Conn, error) {
	if s.singleStream != nil {
		// Server side: we already have the stream from Accept()
		st := s.singleStream
		s.singleStream = nil
		return &libp2pConn{Stream: st}, nil
	}

	stream, err := s.Host.NewStream(ctx, s.PeerID, MaknoonProtocol)
	if err != nil {
		return nil, fmt.Errorf("failed to open libp2p stream: %w", err)
	}
	return &libp2pConn{Stream: stream}, nil
}

// Close gracefully shuts down.
func (s *Libp2pSession) Close() error {
	if s.singleStream != nil {
		s.singleStream.Reset()
	}
	return s.Host.Close()
}

// Libp2pListener implements MuxListener for libp2p.
type Libp2pListener struct {
	Host    host.Host
	streams chan network.Stream
}

func (l *Libp2pListener) Accept() (MuxSession, error) {
	stream, ok := <-l.streams
	if !ok {
		return nil, fmt.Errorf("listener closed")
	}
	return &Libp2pSession{Host: l.Host, singleStream: stream}, nil
}

func (l *Libp2pListener) Addr() net.Addr {
	if len(l.Host.Addrs()) > 0 {
		return &multiaddrAddr{ma: l.Host.Addrs()[0]}
	}
	return nil
}

func (l *Libp2pListener) Close() error {
	l.Host.RemoveStreamHandler(MaknoonProtocol)
	close(l.streams)
	return l.Host.Close()
}

// StartLibp2pListener initializes a libp2p host and registers the stream handler.
func StartLibp2pListener(h host.Host) *Libp2pListener {
	l := &Libp2pListener{
		Host:    h,
		streams: make(chan network.Stream, 100),
	}
	h.SetStreamHandler(MaknoonProtocol, func(s network.Stream) {
		l.streams <- s
	})
	return l
}

// NewLibp2pHost initializes a minimal libp2p host for Maknoon.
func NewLibp2pHost(extraOpts ...libp2p.Option) (host.Host, error) {
	cmgr, err := connmgr.NewConnManager(10, 20)
	if err != nil {
		return nil, err
	}

	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/0",
			"/ip4/0.0.0.0/udp/0/quic-v1",
		),
		libp2p.ConnectionManager(cmgr),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
		libp2p.FallbackDefaults,
	}
	opts = append(opts, extraOpts...)

	return libp2p.New(opts...)
}

// DialLibp2p connects to a remote peer and returns a MuxSession.
func DialLibp2p(ctx context.Context, h host.Host, targetAddr string) (*Libp2pSession, error) {
	ma, err := multiaddr.NewMultiaddr(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid multiaddr: %w", err)
	}

	info, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return nil, fmt.Errorf("failed to get addr info: %w", err)
	}

	if err := h.Connect(ctx, *info); err != nil {
		return nil, fmt.Errorf("failed to connect to peer: %w", err)
	}

	return &Libp2pSession{
		Host:   h,
		PeerID: info.ID,
	}, nil
}
