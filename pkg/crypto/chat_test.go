package crypto

import (
	"context"
	"os"
	"testing"
	"time"
)

const ChatAppIDForTest = "maknoon.io/ghost-chat/test"

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestChatSession_BasicFlow(t *testing.T) {
	if os.Getenv("MAKNOON_ALLOW_NETWORK") != "1" {
		t.Skip("skipping network test (set MAKNOON_ALLOW_NETWORK=1 to enable)")
	}

	host := NewChatSession(ChatAppIDForTest)
	peer := NewChatSession(ChatAppIDForTest)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 1. Start Host
	code, err := host.StartHost(ctx)
	if err != nil {
		t.Fatalf("Host failed to start: %v", err)
	}
	if code == "" {
		t.Fatal("Expected a code, got empty string")
	}

	// 2. Start Peer
	err = peer.StartJoin(ctx, code)
	if err != nil {
		t.Fatalf("Peer failed to join: %v", err)
	}

	// Give the rendezvous server a moment to register both clients on the mailbox
	// This is often where the real failure happens.
	time.Sleep(2 * time.Second)

	// Bidirectional Messaging Test
	messages := []string{"hello", "hi", "how are you?", "doing great!", "bye", "ciao"}

	for i, m := range messages {
		sender := host
		receiver := peer
		senderName := "host"
		if i%2 != 0 {
			sender = peer
			receiver = host
			senderName = "peer"
		}

		t.Logf("Testing message %d from %s: %s", i, senderName, m)

		if err := sender.Send(ctx, m); err != nil {
			t.Fatalf("Send failed for message %d: %v", i, err)
		}

		// Read events until we get the expected message
		// (We might get 'status' events first)
		for {
			select {
			case ev := <-receiver.Events:
				if ev.Type == "status" {
					t.Logf("%s received status: %s", senderName, ev.State)
					continue
				}
				if ev.Type != "message" {
					t.Fatalf("Expected message event, got %s", ev.Type)
				}
				if ev.Text != m {
					t.Fatalf("Message content mismatch. Expected: %s, Got: %s", m, ev.Text)
				}
				goto nextMessage
			case <-ctx.Done():
				t.Fatalf("Timeout waiting for message %d on receiver", i)
			}
		}
	nextMessage:
	}

	host.Close()
	peer.Close()
}
