package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// WormholeAddr represents a virtual address for a Magic Wormhole connection.
type WormholeAddr struct {
	Code string
}

func (a WormholeAddr) Network() string { return "magic-wormhole" }
func (a WormholeAddr) String() string  { return a.Code }

// WormholePacketConn adapts a stream-oriented io.ReadWriteCloser (like a Wormhole Transit stream)
// to the net.PacketConn interface required by QUIC.
type WormholePacketConn struct {
	Stream io.ReadWriteCloser
	Local  WormholeAddr
	Remote WormholeAddr

	readMu  sync.Mutex
	writeMu sync.Mutex

	closeOnce sync.Once
	done      chan struct{}
}

// NewWormholePacketConn initializes a new adapter for the provided stream.
func NewWormholePacketConn(stream io.ReadWriteCloser, localCode, remoteCode string) *WormholePacketConn {
	return &WormholePacketConn{
		Stream: stream,
		Local:  WormholeAddr{Code: localCode},
		Remote: WormholeAddr{Code: remoteCode},
		done:   make(chan struct{}),
	}
}

// ReadFrom reads a framed packet from the Wormhole stream.
func (c *WormholePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// 1. Read 2-byte length header
	var length uint16
	if err := binary.Read(c.Stream, binary.BigEndian, &length); err != nil {
		return 0, nil, err
	}

	if int(length) > len(p) {
		return 0, nil, fmt.Errorf("packet too large: %d > %d", length, len(p))
	}

	// 2. Read exactly 'length' bytes
	n, err = io.ReadFull(c.Stream, p[:length])
	return n, c.Remote, err
}

// WriteTo frames the packet and writes it to the Wormhole stream.
func (c *WormholePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if len(p) > 65535 {
		return 0, fmt.Errorf("packet exceeds maximum framing size")
	}

	// 1. Write 2-byte length header
	if err := binary.Write(c.Stream, binary.BigEndian, uint16(len(p))); err != nil {
		return 0, err
	}

	// 2. Write the packet payload
	return c.Stream.Write(p)
}

// Close gracefully shuts down the adapter and the underlying stream.
func (c *WormholePacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		err = c.Stream.Close()
	})
	return err
}

func (c *WormholePacketConn) LocalAddr() net.Addr  { return c.Local }
func (c *WormholePacketConn) SetDeadline(t time.Time) error {
	// Not strictly applicable to the virtual adapter; handled by underlying stream if supported
	return nil
}
func (c *WormholePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *WormholePacketConn) SetWriteDeadline(t time.Time) error { return nil }
