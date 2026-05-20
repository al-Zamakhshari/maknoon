package crypto

import (
	"bytes"
	"testing"
)

// --- IntPtr / BytePtr helpers ---

func TestIntPtr(t *testing.T) {
	v := 42
	p := IntPtr(v)
	if p == nil {
		t.Fatal("IntPtr returned nil")
	}
	if *p != 42 {
		t.Errorf("*IntPtr(42) = %d, want 42", *p)
	}
}

func TestBytePtr(t *testing.T) {
	p := BytePtr(7)
	if p == nil {
		t.Fatal("BytePtr returned nil")
	}
	if *p != 7 {
		t.Errorf("*BytePtr(7) = %d, want 7", *p)
	}
}

// --- Options.Emit ---

func TestOptionsEmitSendsEvent(t *testing.T) {
	ch := make(chan EngineEvent, 1)
	opts := Options{EventStream: ch}
	opts.Emit("test_event")

	select {
	case ev := <-ch:
		if ev != EngineEvent("test_event") {
			t.Errorf("event = %v, want %q", ev, "test_event")
		}
	default:
		t.Error("no event received on channel")
	}
}

func TestOptionsEmitNilChannel(t *testing.T) {
	// nil EventStream → no-op, must not panic.
	opts := Options{}
	opts.Emit("noop")
}

// --- Concurrency and profile option helpers via ProtectStream ---

func TestOptionsProfileID(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("opts-profile-pass")
	pid := byte(1)
	opts := Options{Passphrase: pass, ProfileID: &pid}

	var ct bytes.Buffer
	if _, err := e.Protect(nil, "p.bin", bytes.NewReader([]byte("data")), &ct, opts); err != nil {
		t.Fatalf("Protect with explicit ProfileID: %v", err)
	}
	if ct.Len() == 0 {
		t.Error("Protect returned empty ciphertext")
	}
}

func TestOptionsConcurrency(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("conc-pass")
	c := 2
	opts := Options{Passphrase: pass, Concurrency: &c}

	var ct bytes.Buffer
	if _, err := e.Protect(nil, "c.bin", bytes.NewReader(bytes.Repeat([]byte("x"), 1024*64)), &ct, opts); err != nil {
		t.Fatalf("Protect with Concurrency=2: %v", err)
	}

	var out bytes.Buffer
	if _, err := e.Unprotect(nil, bytes.NewReader(ct.Bytes()), &out, "", Options{Passphrase: pass, Concurrency: &c}); err != nil {
		t.Fatalf("Unprotect with Concurrency=2: %v", err)
	}
}

// --- TraceID propagation ---

func TestOptionsTraceID(t *testing.T) {
	e := engineForVault(t)
	opts := Options{
		Passphrase: []byte("trace-pass"),
		TraceID:    "test-trace-123",
	}
	var ct bytes.Buffer
	if _, err := e.Protect(nil, "t.bin", bytes.NewReader([]byte("trace test")), &ct, opts); err != nil {
		t.Fatalf("Protect with TraceID: %v", err)
	}
}

// --- Stealth flag ---

func TestOptionsStealth(t *testing.T) {
	e := engineForVault(t)
	stealth := true
	opts := Options{Passphrase: []byte("stealth-pass"), Stealth: &stealth}

	var ct bytes.Buffer
	if _, err := e.Protect(nil, "s.bin", bytes.NewReader([]byte("stealth payload")), &ct, opts); err != nil {
		t.Fatalf("Protect stealth: %v", err)
	}

	// Stealth ciphertext has no magic header — decrypt with stealth=true.
	stealthDecrypt := true
	var out bytes.Buffer
	if _, err := e.Unprotect(nil, bytes.NewReader(ct.Bytes()), &out, "", Options{
		Passphrase: []byte("stealth-pass"),
		Stealth:    &stealthDecrypt,
	}); err != nil {
		t.Fatalf("Unprotect stealth: %v", err)
	}
	if out.String() != "stealth payload" {
		t.Error("stealth round-trip mismatch")
	}
}
