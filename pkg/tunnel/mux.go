package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

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

type connAdapter struct {
	io.ReadWriteCloser
}

func (c *connAdapter) LocalAddr() net.Addr                { return &net.IPAddr{IP: net.IPv4zero} }
func (c *connAdapter) RemoteAddr() net.Addr               { return &net.IPAddr{IP: net.IPv4zero} }
func (c *connAdapter) SetDeadline(t time.Time) error      { return nil }
func (c *connAdapter) SetReadDeadline(t time.Time) error  { return nil }
func (c *connAdapter) SetWriteDeadline(t time.Time) error { return nil }

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
