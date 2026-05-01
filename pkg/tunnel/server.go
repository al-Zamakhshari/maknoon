package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
)

// TunnelServer handles incoming multiplexed connections and forwards them to internal targets.
type TunnelServer struct {
	// Target is the internal address to forward traffic to (e.g. 127.0.0.1:80)
	Target   string
	Listener MuxListener
}

func NewTunnelServer(ln MuxListener) *TunnelServer {
	return &TunnelServer{
		Listener: ln,
	}
}

// Start begins accepting sessions from its listener.
func (s *TunnelServer) Start() error {
	ctx := context.Background()
	return s.Serve(ctx, s.Listener)
}

// Serve begins accepting sessions from a polymorphic MuxListener.
func (s *TunnelServer) Serve(ctx context.Context, ln MuxListener) error {
	defer ln.Close()

	for {
		sess, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleSession(ctx, sess)
	}
}

func (s *TunnelServer) handleSession(ctx context.Context, sess MuxSession) {
	defer sess.Close()

	// If the session is already a single stream (like server-side libp2p),
	// we just handle it directly once.
	if ls, ok := sess.(*Libp2pSession); ok && ls.singleStream != nil {
		conn, _ := ls.OpenStream(ctx)
		s.handleStream(conn)
		return
	}

	for {
		stream, err := sess.OpenStream(ctx)
		if err != nil {
			return
		}
		go s.handleStream(stream)
	}
}

func (s *TunnelServer) handleStream(stream net.Conn) {
	defer stream.Close()

	// 1. Read Destination Header [1 byte len][address string]
	lb := GlobalPool.Get()
	defer GlobalPool.Put(lb)

	if _, err := io.ReadFull(stream, lb.Bytes()[:1]); err != nil {
		slog.Error("tunnel server: failed to read header length", "err", err)
		return
	}
	addrLen := int(lb.Bytes()[0])

	if _, err := io.ReadFull(stream, lb.Bytes()[:addrLen]); err != nil {
		fmt.Fprintf(os.Stderr, "tunnel server: failed to read target address: %v\n", err)
		return
	}
	targetAddr := string(lb.Bytes()[:addrLen])

	fmt.Fprintf(os.Stderr, "tunnel server: forwarding stream to %s\n", targetAddr)

	// 2. Dial the internal target
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tunnel server: failed to dial target %s: %v\n", targetAddr, err)
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
