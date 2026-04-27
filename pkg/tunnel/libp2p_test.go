package tunnel

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestLibp2pProtocols_Skeptical(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test")
	}

	// 1. Give it enough breathing room for this restricted environment
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer h1.Close()

	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()

	// 2. Use a buffered channel to avoid any blocking in the handler
	received := make(chan string, 10)
	h1.SetStreamHandler(MaknoonProtocol, func(s network.Stream) {
		p := s.Conn().RemotePeer().String()
		received <- p
		s.Close()
	})

	// 3. Connect with explicit verification
	if err := h2.Connect(ctx, peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()}); err != nil {
		t.Fatal(err)
	}

	if len(h2.Network().ConnsToPeer(h1.ID())) == 0 {
		t.Fatal("Connect returned but no active connection found")
	}

	// 4. Open stream and WAIT
	t.Logf("Opening stream to %s", h1.ID())
	start := time.Now()
	s, err := h2.NewStream(ctx, h1.ID(), MaknoonProtocol)
	if err != nil {
		t.Fatalf("Failed to open stream after %v: %v", time.Since(start), err)
	}
	s.Close()

	t.Log("Stream call returned, waiting for handler...")
	select {
	case peerID := <-received:
		t.Logf("✅ SUCCESS: Handler fired for peer %s after %v", peerID, time.Since(start))
	case <-ctx.Done():
		t.Errorf("❌ FAILURE: Handler NEVER fired even after 60s. Environment is potentially dropping L7 packets or Go scheduler is starved.")
	}
}
