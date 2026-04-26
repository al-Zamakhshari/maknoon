package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

// YamuxSession implements MuxSession for stream-based transports like Magic Wormhole.
type YamuxSession struct {
	Session *yamux.Session
	raw     io.Closer
}

// OpenStream initiates a new multiplexed stream through the Yamux session.
func (s *YamuxSession) OpenStream(ctx context.Context) (net.Conn, error) {
	return s.Session.Open()
}

// Close gracefully shuts down the Yamux session.
func (s *YamuxSession) Close() error {
	s.Session.Close()
	if s.raw != nil {
		s.raw.Close()
	}
	return nil
}

// connAdapter wraps an io.ReadWriteCloser to satisfy net.Conn
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

	// Adapt io.ReadWriteCloser to net.Conn for yamux
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
