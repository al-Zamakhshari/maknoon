package crypto

import (
	"bytes"
	"os"
	"testing"
)

func TestObserverPattern(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	ResetGlobalConfig()
	engine, err := NewEngine(&HumanPolicy{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	data := make([]byte, ChunkSize*2)
	r := bytes.NewReader(data)
	var w bytes.Buffer

	events := make(chan EngineEvent, 100)
	opts := Options{
		Passphrase:  []byte("test"),
		EventStream: events,
	}

	done := make(chan struct{})
	var chunkCount int
	var handshakeDone bool
	var started bool

	go func() {
		for ev := range events {
			switch ev.(type) {
			case EventEncryptionStarted:
				started = true
			case EventHandshakeComplete:
				handshakeDone = true
			case EventChunkProcessed:
				chunkCount++
			}
		}
		close(done)
	}()

	_, err = engine.Protect(nil, "testfile", r, &w, opts)
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}
	close(events)
	<-done

	if !started {
		t.Error("EventEncryptionStarted not received")
	}
	if !handshakeDone {
		t.Error("EventHandshakeComplete not received")
	}
	if chunkCount == 0 {
		t.Error("EventChunkProcessed not received")
	}

	// Test Decryption events
	decR := bytes.NewReader(w.Bytes())
	var decW bytes.Buffer
	decEvents := make(chan EngineEvent, 100)
	opts.EventStream = decEvents

	doneDec := make(chan struct{})
	var decStarted bool
	var decHandshake bool

	go func() {
		for ev := range decEvents {
			switch ev.(type) {
			case EventDecryptionStarted:
				decStarted = true
			case EventHandshakeComplete:
				decHandshake = true
			}
		}
		close(doneDec)
	}()

	_, err = engine.Unprotect(nil, decR, &decW, "", opts)
	if err != nil {
		t.Fatalf("Unprotect failed: %v", err)
	}
	close(decEvents)
	<-doneDec

	if !decStarted {
		t.Error("EventDecryptionStarted not received")
	}
	if !decHandshake {
		t.Error("EventHandshakeComplete not received")
	}
}
