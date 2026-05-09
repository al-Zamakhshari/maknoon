package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
)

func TestResilientTunnelChaos(t *testing.T) {
	// Setup 3 sub-sessions (1 data + 2 parity for extreme resilience)
	subs := make([]MuxSession, 3)
	for i := 0; i < 3; i++ {
		subs[i] = &MockMuxSession{ID: i}
	}

	resSess, err := NewResilientMuxSession(subs, 1, 2)
	if err != nil {
		t.Fatalf("failed to create resilient session: %v", err)
	}

	ctx := context.Background()
	conn, err := resSess.OpenStream(ctx)
	if err != nil {
		t.Fatalf("failed to open resilient stream: %v", err)
	}
	defer conn.Close()

	rConn := conn.(*ResilientConn)

	// 1. Initial Write/Read
	msg := []byte("Initial Resilient Packet")
	go func() {
		_, _ = conn.Write(msg)
	}()

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("initial read failed: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Errorf("mismatch: %s", string(buf[:n]))
	}

	// 2. CHAOS: Kill 2 out of 3 lanes (Parity allows up to 2 lane losses if data=1)
	fmt.Println("🔥 Sabotaging lanes 1 and 2...")
	rConn.Lanes[1].Close()
	rConn.Lanes[2].Close()
	rConn.Lanes[1] = nil
	rConn.Lanes[2] = nil

	// 3. Post-Chaos Write/Read (Should still work)
	msg2 := []byte("Resilient Packet After Lane Failure")
	go func() {
		_, _ = conn.Write(msg2)
	}()

	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("post-chaos read failed: %v", err)
	}
	if string(buf[:n]) != string(msg2) {
		t.Errorf("mismatch after chaos: %s", string(buf[:n]))
	}

	fmt.Println("✅ Chaos Test Passed: Connection survived lane loss.")
}

// MockMuxSession for chaos testing
type MockMuxSession struct {
	ID int
}

func (m *MockMuxSession) OpenStream(ctx context.Context) (net.Conn, error) {
	s1, s2 := net.Pipe()
	go io.Copy(s1, s1) // Echo server
	return s2, nil
}

func (m *MockMuxSession) Close() error { return nil }
