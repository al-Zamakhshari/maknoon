package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
)

// TunnelServer handles incoming multiplexed connections and forwards them to internal targets.
type TunnelServer struct {
	// Target is the internal address to forward traffic to (e.g. 127.0.0.1:80)
	Target string
}

// Serve begins accepting sessions from a polymorphic MuxListener.
func (s *TunnelServer) Serve(ctx context.Context, ln MuxListener) error {
	defer ln.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			sess, err := ln.Accept()
			if err != nil {
				return err
			}
			go s.handleSession(ctx, sess)
		}
	}
}

func (s *TunnelServer) handleSession(ctx context.Context, sess MuxSession) {
	defer sess.Close()

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
