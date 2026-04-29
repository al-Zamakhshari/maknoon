package crypto

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

const P2PChatProtocol = "/maknoon/chat/1.0.0"

// ChatEvent represents a synchronized event in the chat stream.
type ChatEvent struct {
	ID        string `json:"id"`
	Seq       uint64 `json:"seq"`
	Type      string `json:"type"`   // "message", "status", "error"
	Sender    string `json:"sender"` // "me", "peer", "system"
	Text      string `json:"text,omitempty"`
	Timestamp int64  `json:"timestamp"`
	State     string `json:"state,omitempty"` // for status events
}

// P2PChatSession handles an identity-bound persistent chat session over libp2p.
type P2PChatSession struct {
	Host   host.Host
	Events chan ChatEvent
	done   chan struct{}
	stream network.Stream
}

// NewP2PChatSession creates a new libp2p-based chat session.
func NewP2PChatSession(h host.Host) *P2PChatSession {
	return &P2PChatSession{
		Host:   h,
		Events: make(chan ChatEvent, 100),
		done:   make(chan struct{}),
	}
}

// Multiaddrs returns the host's multiaddrs for direct connectivity.
func (s *P2PChatSession) Multiaddrs() []string {
	var res []string
	for _, addr := range s.Host.Addrs() {
		res = append(res, fmt.Sprintf("%s/p2p/%s", addr, s.Host.ID()))
	}
	return res
}

// StartHost registers the chat protocol and waits for a peer.
func (s *P2PChatSession) StartHost(ctx context.Context) (string, error) {
	s.Host.SetStreamHandler(P2PChatProtocol, func(stream network.Stream) {
		if s.stream != nil {
			stream.Reset() // Already in a session
			return
		}
		s.stream = stream
		s.Events <- ChatEvent{Type: "status", State: "peer-joined", Sender: "system"}
		go s.readLoop()
	})

	return s.Host.ID().String(), nil
}

// StartJoin dials a remote peer to start a chat.
func (s *P2PChatSession) StartJoin(ctx context.Context, target string) error {
	pID, err := peer.Decode(target)
	if err != nil {
		return fmt.Errorf("invalid PeerID: %w", err)
	}

	stream, err := s.Host.NewStream(ctx, pID, P2PChatProtocol)
	if err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}

	s.stream = stream
	s.Events <- ChatEvent{Type: "status", State: "connected", Sender: "system"}
	go s.readLoop()
	return nil
}

func (s *P2PChatSession) readLoop() {
	defer s.Close()
	decoder := json.NewDecoder(s.stream)

	for {
		var ev ChatEvent
		if err := decoder.Decode(&ev); err != nil {
			if err != io.EOF {
				slog.Error("chat: read error", "err", err)
			}
			return
		}
		ev.Sender = "peer"
		ev.Timestamp = time.Now().Unix()
		s.Events <- ev
	}
}

// Send sends a message over the libp2p stream.
func (s *P2PChatSession) Send(ctx context.Context, text string) error {
	if s.stream == nil {
		return fmt.Errorf("session not established")
	}

	ev := ChatEvent{
		Type:      "message",
		Sender:    "me",
		Text:      text,
		Timestamp: time.Now().Unix(),
	}

	encoder := json.NewEncoder(s.stream)
	if err := encoder.Encode(ev); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	return nil
}

// Close terminates the chat session.
func (s *P2PChatSession) Close() {
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}
	if s.stream != nil {
		s.stream.Close()
	}
}
