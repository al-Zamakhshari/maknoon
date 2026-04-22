package crypto

import (
	"bytes"
	"testing"
)

func TestPublicKeyDerivation(t *testing.T) {
	kpub, kpriv, spub, spriv, _, npriv, err := GeneratePQKeyPair()
	if err != nil {
		t.Fatalf("GeneratePQKeyPair failed: %v", err)
	}
	defer SafeClear(kpriv)
	defer SafeClear(spriv)
	defer SafeClear(npriv)

	t.Run("DeriveKEMPublic", func(t *testing.T) {
		derived, err := DeriveKEMPublic(kpriv)
		if err != nil {
			t.Fatalf("DeriveKEMPublic failed: %v", err)
		}
		if !bytes.Equal(derived, kpub) {
			t.Error("Derived KEM public key mismatch")
		}
	})

	t.Run("DeriveSIGPublic", func(t *testing.T) {
		derived, err := DeriveSIGPublic(spriv)
		if err != nil {
			t.Fatalf("DeriveSIGPublic failed: %v", err)
		}
		if !bytes.Equal(derived, spub) {
			t.Error("Derived SIG public key mismatch")
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
