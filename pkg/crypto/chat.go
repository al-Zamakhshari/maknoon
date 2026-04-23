package crypto

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/psanford/wormhole-william/rendezvous"
	"github.com/psanford/wormhole-william/wordlist"
)

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

// ChatSession handles a reliable P2P chat session.
type ChatSession struct {
	AppID  string
	SideID string
	Code   string

	RendezvousURL string
	Rendezvous    *rendezvous.Client
	Events        chan ChatEvent
	done          chan struct{}

	// Synchronization State
	mu          sync.Mutex
	nextSendSeq uint64
	recvSeqs    map[string]uint64               // next expected seq per peer side
	seenMsgs    map[string]bool                 // Deduplication for mailbox replays
	pendingMsgs map[string]map[uint64]ChatEvent // per-side reordering buffer
	handshakeOK bool
}

// NewChatSession creates a new reliable chat session.
func NewChatSession(appID string) *ChatSession {
	sideID := fmt.Sprintf("%x", time.Now().UnixNano())
	return &ChatSession{
		AppID:       appID,
		SideID:      sideID,
		Events:      make(chan ChatEvent, 100),
		done:        make(chan struct{}),
		seenMsgs:    make(map[string]bool),
		recvSeqs:    make(map[string]uint64),
		pendingMsgs: make(map[string]map[uint64]ChatEvent),
		nextSendSeq: 1,
	}
}

// StartHost starts a chat session as a host.
func (s *ChatSession) StartHost(ctx context.Context) (string, error) {
	url := s.RendezvousURL
	if url == "" {
		url = GetGlobalConfig().Wormhole.RendezvousURL
	}
	s.Rendezvous = rendezvous.NewClient(url, s.SideID, s.AppID)
	if _, err := s.Rendezvous.Connect(ctx); err != nil {
		return "", err
	}

	nameplate, err := s.Rendezvous.CreateMailbox(ctx)
	if err != nil {
		return "", err
	}

	s.Code = nameplate + "-" + wordlist.ChooseWords(2)
	go s.listenLoop(ctx)

	// Send initial handshake
	_ = s.Rendezvous.AddMessage(ctx, "handshake", "ping")

	return s.Code, nil
}

// StartJoin joins an existing chat session.
func (s *ChatSession) StartJoin(ctx context.Context, code string) error {
	s.Code = code
	url := s.RendezvousURL
	if url == "" {
		url = GetGlobalConfig().Wormhole.RendezvousURL
	}
	s.Rendezvous = rendezvous.NewClient(url, s.SideID, s.AppID)
	if _, err := s.Rendezvous.Connect(ctx); err != nil {
		return err
	}

	parts := strings.Split(code, "-")
	if len(parts) < 1 {
		return fmt.Errorf("invalid code")
	}

	if err := s.Rendezvous.AttachMailbox(ctx, parts[0]); err != nil {
		return err
	}

	go s.listenLoop(ctx)

	// Send initial handshake
	_ = s.Rendezvous.AddMessage(ctx, "handshake", "ping")

	return nil
}

func (s *ChatSession) listenLoop(ctx context.Context) {
	msgChan := s.Rendezvous.MsgChan(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case ev, ok := <-msgChan:
			if !ok {
				return
			}
			if ev.Side == s.SideID {
				continue
			}

			s.mu.Lock()
			msgKey := ev.Side + ":" + ev.Phase
			if s.seenMsgs[msgKey] {
				s.mu.Unlock()
				continue
			}
			s.seenMsgs[msgKey] = true

			if ev.Phase == "handshake" {
				if !s.handshakeOK {
					s.handshakeOK = true
					s.Events <- ChatEvent{Type: "status", State: "peer-joined", Sender: "system"}
					_ = s.Rendezvous.AddMessage(ctx, "handshake", "pong")
				}
				s.mu.Unlock()
				continue
			}

			// Parse sequence number from phase
			var seq uint64
			n, _ := fmt.Sscanf(ev.Phase, "%d", &seq)
			if n == 1 {
				event := ChatEvent{
					ID:        ev.Phase,
					Seq:       seq,
					Type:      "message",
					Sender:    "peer",
					Text:      ev.Body,
					Timestamp: time.Now().Unix(),
				}

				if s.pendingMsgs[ev.Side] == nil {
					s.pendingMsgs[ev.Side] = make(map[uint64]ChatEvent)
					s.recvSeqs[ev.Side] = 1
				}
				s.pendingMsgs[ev.Side][seq] = event
				s.processSequencedMessages(ev.Side)
			}
			s.mu.Unlock()
		}
	}
}

// processSequencedMessages pushes messages from a specific peer to the event channel in the correct order.
func (s *ChatSession) processSequencedMessages(side string) {
	for {
		next := s.recvSeqs[side]
		ev, exists := s.pendingMsgs[side][next]
		if !exists {
			break
		}
		delete(s.pendingMsgs[side], next)
		s.Events <- ev
		s.recvSeqs[side] = next + 1
	}
}

// Send sends a message to the peer with a monotonic sequence number.
func (s *ChatSession) Send(ctx context.Context, text string) error {
	s.mu.Lock()
	seq := s.nextSendSeq
	s.nextSendSeq++
	phase := fmt.Sprintf("%d", seq)
	msgKey := s.SideID + ":" + phase
	s.seenMsgs[msgKey] = true
	s.mu.Unlock()

	return s.Rendezvous.AddMessage(ctx, phase, text)
}

// Close closes the session cleanly.
func (s *ChatSession) Close() {
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}
	if s.Rendezvous != nil {
		s.Rendezvous.Close(context.Background(), rendezvous.Happy)
	}
}
