package crypto

import (
	"bytes"
	"testing"
)

// TestGetProfileValid verifies known profile IDs return non-nil profiles.
func TestGetProfileValid(t *testing.T) {
	for _, id := range []byte{1, 3} {
		p, err := GetProfile(id, nil)
		if err != nil {
			t.Errorf("GetProfile(%d): %v", id, err)
			continue
		}
		if p == nil {
			t.Errorf("GetProfile(%d) returned nil", id)
		}
		if p.ID() != id {
			t.Errorf("GetProfile(%d).ID() = %d", id, p.ID())
		}
	}
}

func TestGetProfileUnknown(t *testing.T) {
	_, err := GetProfile(255, nil)
	if err == nil {
		t.Error("expected error for unknown profile ID 255")
	}
}

func TestDefaultProfile(t *testing.T) {
	p := DefaultProfile()
	if p == nil {
		t.Fatal("DefaultProfile returned nil")
	}
	if p.ID() == 0 {
		t.Error("DefaultProfile ID should not be 0")
	}
}

func TestRegisterAndGetCustomProfile(t *testing.T) {
	// Use a minimal valid DynamicProfile with a unique test ID.
	dp := &DynamicProfile{
		CustomID:   200,
		CustomSalt: 16,
		CustomNonc: 12,
	}
	RegisterProfile(dp)

	got, err := GetProfile(dp.ID(), nil)
	if err != nil {
		t.Fatalf("GetProfile after Register: %v", err)
	}
	if got.ID() != dp.ID() {
		t.Errorf("got ID %d, want %d", got.ID(), dp.ID())
	}
}

func TestProfileSaltSize(t *testing.T) {
	p := DefaultProfile()
	if p.SaltSize() <= 0 {
		t.Errorf("SaltSize = %d, want > 0", p.SaltSize())
	}
}

func TestProfileDeriveKey(t *testing.T) {
	p := DefaultProfile()
	salt := make([]byte, p.SaltSize())
	k1 := p.DeriveKey([]byte("pass"), salt)
	k2 := p.DeriveKey([]byte("pass"), salt)
	if len(k1) != 32 {
		t.Errorf("key length = %d, want 32", len(k1))
	}
	if !bytes.Equal(k1, k2) {
		t.Error("DeriveKey is not deterministic")
	}
	k3 := p.DeriveKey([]byte("different"), salt)
	if bytes.Equal(k1, k3) {
		t.Error("different passphrases should produce different keys")
	}
}

func TestSafeClearString(t *testing.T) {
	s := []string{"secret1", "secret2", "secret3"}
	SafeClearString(s)
	for i, v := range s {
		if v != "" {
			t.Errorf("s[%d] not cleared: %q", i, v)
		}
	}
}
