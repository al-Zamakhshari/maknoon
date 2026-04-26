package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/hashicorp/yamux"
)

// YamuxSession implements MuxSession for stream-based transports.
type YamuxSession struct {
	Session *yamux.Session
	raw     io.Closer
}

func (s *YamuxSession) OpenStream(ctx context.Context) (net.Conn, error) {
	return s.Session.Open()
}

func (s *YamuxSession) Close() error {
	s.Session.Close()
	if s.raw != nil {
		s.raw.Close()
	}
	return nil
}

// TCPListener implements MuxListener for TCP+Yamux fallback.
type TCPListener struct {
	net.Listener
}

func (l *TCPListener) Accept() (MuxSession, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return WrapYamux(conn, true)
}

func (l *TCPListener) Addr() net.Addr {
	return l.Listener.Addr()
}

func (l *TCPListener) Close() error {
	return l.Listener.Close()
}

// WrapYamux initializes a Yamux session over an existing reliable stream.
func WrapYamux(stream io.ReadWriteCloser, isServer bool) (*YamuxSession, error) {
	var session *yamux.Session
	var err error

	conn := &connAdapter{stream}
	config := yamux.DefaultConfig()
	config.EnableKeepAlive = true

	if isServer {
		session, err = yamux.Server(conn, config)
	} else {
		session, err = yamux.Client(conn, config)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to initialize yamux session: %w", err)
	}

	return &YamuxSession{Session: session, raw: stream}, nil
}

// NOTE: Ghost Tunneling via libp2p is now the standard for Maknoon v3.0.
// We've moved away from experimental pipe hacks for reliable stream multiplexing.
