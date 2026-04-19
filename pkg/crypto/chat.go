package crypto

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/psanford/wormhole-william/rendezvous"
	"github.com/psanford/wormhole-william/wormhole"
)

// ChatEvent represents an event in the chat stream.
type ChatEvent struct {
	Type      string `json:"type"`      // "message", "status", "error"
	Sender    string `json:"sender"`    // "me", "peer", "system"
	Text      string `json:"text,omitempty"`
	Timestamp int64  `json:"timestamp"`
	State     string `json:"state,omitempty"` // for status events
}

// ChatSession handles a P2P chat session using the wormhole infrastructure.
type ChatSession struct {
	Client  wormhole.Client
	AppID   string
	SideID  string
	Code    string
	
	// Crypto
	SharedKey []byte
	Profile   Profile
	
	Rendezvous *rendezvous.Client
	
	Events chan ChatEvent
	done   chan struct{}
}

// NewChatSession creates a new chat session.
func NewChatSession(appID string) *ChatSession {
	sideID := fmt.Sprintf("%x", time.Now().UnixNano())
	return &ChatSession{
		AppID:   appID,
		SideID:  sideID,
		Events:  make(chan ChatEvent, 100),
		done:    make(chan struct{}),
		Profile: DefaultProfile(),
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

	// For the Ghost Chat MVP, we use the mailbox directly for PAKE-less exchange.
	// In a real implementation, we'd add PAKE here.
	s.Code = nameplate + "-ghost-chat"
	
	go s.listenLoop(ctx)
	
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
		case ev := <-msgChan:
			if ev.Side != s.SideID {
				// We received a message from the peer.
				// For the MVP, it's plaintext. In v2, we add XChaCha20-Poly1305.
				s.Events <- ChatEvent{
					Type:      "message",
					Sender:    "peer",
					Text:      ev.Body,
					Timestamp: time.Now().Unix(),
				}
			}
		}
	}
}

// Send sends a message to the peer.
func (s *ChatSession) Send(ctx context.Context, text string) error {
	// Unique phase for each message to avoid mailbox collisions
	phase := fmt.Sprintf("msg-%d-%s", time.Now().UnixNano(), s.SideID)
	return s.Rendezvous.AddMessage(ctx, phase, text)
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
