package crypto

import (
	"bytes"
	"testing"
)

func TestPublicKeyDerivation(t *testing.T) {
	kpub, kpriv, spub, spriv, err := GeneratePQKeyPair()
	if err != nil {
		t.Fatalf("GeneratePQKeyPair failed: %v", err)
	}
	defer SafeClear(kpriv)
	defer SafeClear(spriv)

	t.Run("DeriveKEMPublic", func(t *testing.T) {
		derived, err := DeriveKEMPublic(kpriv)
		if err != nil {
			t.Fatalf("DeriveKEMPublic failed: %v", err)
		}
		if !bytes.Equal(kpub, derived) {
			t.Errorf("Derived KEM public key does not match original")
		}
	})

	t.Run("DeriveSIGPublic", func(t *testing.T) {
		derived, err := DeriveSIGPublic(spriv)
		if err != nil {
			t.Fatalf("DeriveSIGPublic failed: %v", err)
		}
		if !bytes.Equal(spub, derived) {
			t.Errorf("Derived SIG public key does not match original")
		}
	})

	t.Run("InvalidKeys", func(t *testing.T) {
		_, err := DeriveKEMPublic([]byte("invalid-key"))
		if err == nil {
			t.Error("Expected error for invalid KEM key, got nil")
		}
		_, err = DeriveSIGPublic([]byte("invalid-key"))
		if err == nil {
			t.Error("Expected error for invalid SIG key, got nil")
		}
	})
}
