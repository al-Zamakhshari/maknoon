package crypto

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/psanford/wormhole-william/rendezvous"
	"github.com/psanford/wormhole-william/wordlist"
	"github.com/psanford/wormhole-william/wormhole"
)

// ChatEvent represents an event in the chat stream.
type ChatEvent struct {
	ID        string `json:"id"`
	Type      string `json:"type"`   // "message", "status", "error"
	Sender    string `json:"sender"` // "me", "peer", "system"
	Text      string `json:"text,omitempty"`
	Timestamp int64  `json:"timestamp"`
	State     string `json:"state,omitempty"` // for status events
}

// ChatSession handles a P2P chat session using the wormhole infrastructure.
type ChatSession struct {
	Client wormhole.Client
	AppID  string
	SideID string
	Code   string

	Rendezvous *rendezvous.Client

	Events chan ChatEvent
	done   chan struct{}

	seenMsgs map[string]bool
	mu       sync.Mutex
}

// NewChatSession creates a new chat session.
func NewChatSession(appID string) *ChatSession {
	sideID := fmt.Sprintf("%x", time.Now().UnixNano())
	return &ChatSession{
		AppID:    appID,
		SideID:   sideID,
		Events:   make(chan ChatEvent, 100),
		done:     make(chan struct{}),
		seenMsgs: make(map[string]bool),
	}
}

// StartHost starts a chat session as a host.
func (s *ChatSession) StartHost(ctx context.Context) (string, error) {
	s.Rendezvous = rendezvous.NewClient(wormhole.DefaultRendezvousURL, s.SideID, s.AppID)
	_, err := s.Rendezvous.Connect(ctx)
	if err != nil {
		return "", err
	}

	nameplate, err := s.Rendezvous.CreateMailbox(ctx)
	if err != nil {
		return "", err
	}

	// We use the standard wormhole wordlist for high-entropy codes.
	s.Code = nameplate + "-" + wordlist.ChooseWords(2)

	go s.listenLoop(ctx)

	// Send an initial silent handshake to announce presence
	_ = s.Rendezvous.AddMessage(ctx, "handshake", "ping")

	return s.Code, nil
}

// StartJoin joins an existing chat session.
func (s *ChatSession) StartJoin(ctx context.Context, code string) error {
	s.Code = code
	s.Rendezvous = rendezvous.NewClient(wormhole.DefaultRendezvousURL, s.SideID, s.AppID)
	_, err := s.Rendezvous.Connect(ctx)
	if err != nil {
		return err
	}

	parts := strings.Split(code, "-")
	if len(parts) < 1 {
		return fmt.Errorf("invalid code")
	}

	err = s.Rendezvous.AttachMailbox(ctx, parts[0])
	if err != nil {
		return err
	}

	go s.listenLoop(ctx)

	// Send an initial silent handshake to announce presence
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
			if ev.Side != s.SideID {
				s.mu.Lock()
				if s.seenMsgs[ev.Phase] {
					s.mu.Unlock()
					continue
				}
				s.seenMsgs[ev.Phase] = true
				s.mu.Unlock()

				if ev.Phase == "handshake" {
					s.Events <- ChatEvent{
						Type:   "status",
						State:  "peer-joined",
						Sender: "system",
					}
					continue
				}

				// If it's a phase we haven't seen, it's a new message
				if strings.HasPrefix(ev.Phase, "msg-") {
					s.Events <- ChatEvent{
						ID:        ev.Phase,
						Type:      "message",
						Sender:    "peer",
						Text:      ev.Body,
						Timestamp: time.Now().Unix(),
					}
				}
			}
		}
	}
}

// Send sends a message to the peer.
func (s *ChatSession) Send(ctx context.Context, text string) error {
	// Use a unique ID with 'msg-' prefix as expected by the receiver's filter
	msgID := fmt.Sprintf("msg-%d-%s", time.Now().UnixNano(), s.SideID)

	s.mu.Lock()
	s.seenMsgs[msgID] = true
	s.mu.Unlock()

	return s.Rendezvous.AddMessage(ctx, msgID, text)
}

// Close closes the session.
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
