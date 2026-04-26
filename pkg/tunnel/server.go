package tunnel

import (
	"context"
	"fmt"
	"github.com/quic-go/quic-go"
	"io"
	"log/slog"
	"net"
)

// TunnelServer handles incoming multiplexed connections and forwards them to internal targets.
type TunnelServer struct {
	Listener *quic.Listener
	Session  *YamuxSession
}

// Start begins accepting QUIC connections.
func (s *TunnelServer) Start(ctx context.Context) error {
	if s.Listener == nil {
		return fmt.Errorf("QUIC listener not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		conn, err := s.Listener.Accept(ctx)
		if err != nil {
			return err
		}
		go s.handleQUICConnection(conn)
	}
}

// StartYamux begins accepting streams from a Yamux session.
func (s *TunnelServer) StartYamux(ctx context.Context) error {
	if s.Session == nil {
		return fmt.Errorf("Yamux session not initialized")
	}
	for {
		stream, err := s.Session.Session.Accept()
		if err != nil {
			return err
		}
		go s.handleStream(stream)
	}
}

func (s *TunnelServer) handleQUICConnection(conn *quic.Conn) {
	state := conn.ConnectionState()
	slog.Info("tunnel server: new connection established",
		"remote", conn.RemoteAddr(),
		"curve_id", fmt.Sprintf("0x%04x", state.TLS.CurveID),
	)
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go s.handleStream(&quicConn{rawStream: stream, session: conn})
	}
}

func (s *TunnelServer) handleStream(stream net.Conn) {
	defer stream.Close()

	// 1. Read Destination Header [1 byte len][address string]
	lb := GlobalPool.Get()
	defer GlobalPool.Put(lb)

	if _, err := io.ReadFull(stream, lb.Bytes()[:1]); err != nil {
		return
	}
	addrLen := int(lb.Bytes()[0])

	if _, err := io.ReadFull(stream, lb.Bytes()[:addrLen]); err != nil {
		return
	}
	targetAddr := string(lb.Bytes()[:addrLen])

	slog.Info("tunnel server: forwarding stream", "target", targetAddr)

	// 2. Dial the internal target
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		slog.Error("tunnel server: failed to dial target", "target", targetAddr, "err", err)
		return
	}
	defer target.Close()

	// 3. Bi-directional Multiplexed Bridge
	done := make(chan struct{}, 2)

	go func() {
		lbIn := GlobalPool.Get()
		defer GlobalPool.Put(lbIn)
		io.CopyBuffer(target, stream, lbIn.Bytes())
		done <- struct{}{}
	}()

	go func() {
		lbOut := GlobalPool.Get()
		defer GlobalPool.Put(lbOut)
		io.CopyBuffer(stream, target, lbOut.Bytes())
		done <- struct{}{}
	}()

	<-done
}
