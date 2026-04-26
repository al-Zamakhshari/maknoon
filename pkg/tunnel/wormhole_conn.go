package tunnel

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/psanford/wormhole-william/wormhole"
)

// WormholePacketConn adapts a generic io.ReadWriteCloser to net.PacketConn for QUIC.
type WormholePacketConn struct {
	Stream io.ReadWriteCloser
	readMu sync.Mutex
}

func (c *WormholePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var length uint16
	if err := binary.Read(c.Stream, binary.BigEndian, &length); err != nil {
		return 0, nil, err
	}
	n, err := io.ReadFull(c.Stream, p[:length])
	return n, &net.UDPAddr{IP: net.IPv4zero, Port: 0}, err
}

func (c *WormholePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := binary.Write(c.Stream, binary.BigEndian, uint16(len(p))); err != nil {
		return 0, err
	}
	return c.Stream.Write(p)
}

func (c *WormholePacketConn) Close() error                       { return c.Stream.Close() }
func (c *WormholePacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (c *WormholePacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *WormholePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *WormholePacketConn) SetWriteDeadline(t time.Time) error { return nil }

// EstablishGhostStream performs the Magic Wormhole handshake to get a raw data pipe.
func EstablishGhostStream(ctx context.Context, rendezvous, code string, isServer bool) (io.ReadWriteCloser, error) {
	c := wormhole.Client{RendezvousURL: rendezvous}
	
	if !isServer {
		msg, err := c.Receive(ctx, code)
		if err != nil {
			return nil, err
		}
		// IncomingMessage is a Reader, but not a Closer.
		return &transitBridge{Reader: msg, Writer: io.Discard, closeFunc: func() error { return nil }}, nil
	}
	
	pr, pw := io.Pipe()
	go func() {
		_, status, _ := c.SendFile(ctx, "ghost-tunnel", &pipeSeeker{pr})
		for range status {}
	}()

	return &transitBridge{Reader: pr, Writer: pw, closeFunc: pw.Close}, nil
}

type transitBridge struct {
	io.Reader
	io.Writer
	closeFunc func() error
}

func (b *transitBridge) Close() error {
	if b.closeFunc != nil {
		return b.closeFunc()
	}
	return nil
}

type pipeSeeker struct{ io.Reader }
func (p *pipeSeeker) Seek(offset int64, whence int) (int64, error) { return 0, nil }
