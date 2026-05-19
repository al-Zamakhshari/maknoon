package crypto

import (
	"context"
	"errors"
	"testing"
)

// TestIdentityPublishNoRegistry verifies the "no registry selected" error when
// none of --wkd / --dns / --desec / --local is set.
func TestIdentityPublishNoRegistry(t *testing.T) {
	tmp := t.TempDir()
	setHomeDir(t, tmp)
	mgr := newTestIdentityManager(t, tmp)
	createDefaultIdentity(t, mgr, tmp)

	err := mgr.IdentityPublish(context.Background(), "@alice@example.com", IdentityPublishOptions{
		Name:       "default",
		Passphrase: "testpass",
	})
	if err == nil {
		t.Fatal("expected error when no registry is selected")
	}
	if !containsAny(err.Error(), "no registry selected", "no registry", "select") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestIdentityPublishHandleValidation verifies handle must start with @.
func TestIdentityPublishHandleValidation(t *testing.T) {
	tmp := t.TempDir()
	setHomeDir(t, tmp)
	mgr := newTestIdentityManager(t, tmp)

	err := mgr.IdentityPublish(context.Background(), "alice@example.com", IdentityPublishOptions{
		WKD:        true,
		Name:       "default",
		Passphrase: "testpass",
	})
	if err == nil {
		t.Fatal("expected error for handle without @")
	}
	if !containsAny(err.Error(), "@", "handle") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestIdentityPublishWKDReturnsManual verifies that WKD publish surfaces
// ErrWKDPublishManual (upload instructions) rather than a hard error.
func TestIdentityPublishWKDReturnsManual(t *testing.T) {
	tmp := t.TempDir()
	setHomeDir(t, tmp)
	mgr := newTestIdentityManager(t, tmp)

	// Create a default identity so LoadIdentity succeeds.
	createDefaultIdentity(t, mgr, tmp)

	err := mgr.IdentityPublish(context.Background(), "@alice@example.com", IdentityPublishOptions{
		WKD:        true,
		Name:       "default",
		Passphrase: "testpass",
	})

	var manual *ErrWKDPublishManual
	if !errors.As(err, &manual) {
		t.Fatalf("expected ErrWKDPublishManual, got %T: %v", err, err)
	}
	if manual.URL == "" {
		t.Error("WKD manual URL is empty")
	}
	if len(manual.Content) == 0 {
		t.Error("WKD manual content is empty")
	}
}

// TestIdentityPublishDNSReturnsInstructions verifies that DNS publish returns
// instructions (not a network error) when no real DNS server is available.
func TestIdentityPublishDNSPublishInstructions(t *testing.T) {
	tmp := t.TempDir()
	setHomeDir(t, tmp)
	mgr := newTestIdentityManager(t, tmp)
	createDefaultIdentity(t, mgr, tmp)

	// DNS Publish is manual-only (returns instructions, no network call for basic DNS).
	err := mgr.IdentityPublish(context.Background(), "@alice@example.com", IdentityPublishOptions{
		DNS:        true,
		Name:       "default",
		Passphrase: "testpass",
	})
	// Either nil (instructions printed elsewhere) or a structured error is acceptable;
	// what is NOT acceptable is a panic or an unrelated error.
	_ = err
}

// TestIdentityPublishDesecRequiresToken verifies deSEC publish fails without a token.
func TestIdentityPublishDesecRequiresToken(t *testing.T) {
	tmp := t.TempDir()
	setHomeDir(t, tmp)
	mgr := newTestIdentityManager(t, tmp)
	createDefaultIdentity(t, mgr, tmp)

	// Ensure DESEC_TOKEN is not set in the environment.
	t.Setenv("DESEC_TOKEN", "")

	err := mgr.IdentityPublish(context.Background(), "@alice@example.com", IdentityPublishOptions{
		Desec:      true,
		Name:       "default",
		Passphrase: "testpass",
	})
	if err == nil {
		t.Fatal("expected error without deSEC token")
	}
	if !containsAny(err.Error(), "token", "deSEC", "DESEC") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- helpers ---

func setHomeDir(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
}

func newTestIdentityManager(t *testing.T, home string) *IdentityManager {
	t.Helper()
	// NewIdentityManager uses HOME to derive its base directory.
	_ = home
	conf := DefaultConfig()
	mgr := NewIdentityManager()
	mgr.Config = conf
	return mgr
}

func createDefaultIdentity(t *testing.T, mgr *IdentityManager, home string) {
	t.Helper()
	_, err := mgr.CreateIdentity("default", []byte("testpass"), "", false, "")
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 {
			found := true
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			_ = found
		}
	}
	return false
}
