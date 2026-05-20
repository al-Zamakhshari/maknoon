package crypto

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// --- Entropy ---

func TestGetRandomBytes(t *testing.T) {
	buf := make([]byte, 32)
	if err := GetRandomBytes(buf); err != nil {
		t.Fatalf("GetRandomBytes: %v", err)
	}
	// Should not be all zeros.
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("GetRandomBytes returned all-zero buffer")
	}
}

func TestGetRandomBytesUnique(t *testing.T) {
	a, b := make([]byte, 16), make([]byte, 16)
	GetRandomBytes(a)
	GetRandomBytes(b)
	if bytes.Equal(a, b) {
		t.Error("two GetRandomBytes calls returned identical bytes")
	}
}

func TestEntropySentinelRead(t *testing.T) {
	// EntropySentinel wraps a reader and detects stuck entropy (CRNGT).
	// Normal operation: should read without panic.
	s := NewEntropySentinel(bytes.NewReader(bytes.Repeat([]byte{0xAB}, 128)))
	buf := make([]byte, 32)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("EntropySentinel.Read: %v", err)
	}
	if n != 32 {
		t.Errorf("Read %d bytes, want 32", n)
	}
}

// --- ProfileV3 ---

func testProfileV3(t *testing.T) *ProfileV3 {
	t.Helper()
	p, err := GetProfile(3, nil)
	if err != nil {
		t.Fatalf("GetProfile(3): %v", err)
	}
	pv3, ok := p.(*ProfileV3)
	if !ok {
		t.Fatalf("profile 3 is not *ProfileV3")
	}
	return pv3
}

func TestProfileV3ID(t *testing.T) {
	if testProfileV3(t).ID() != 3 {
		t.Error("ProfileV3.ID() != 3")
	}
}

func TestProfileV3Name(t *testing.T) {
	if testProfileV3(t).Name() != "conservative" {
		t.Errorf("ProfileV3.Name() = %q, want %q", testProfileV3(t).Name(), "conservative")
	}
}

func TestProfileV3SaltAndNonce(t *testing.T) {
	p := testProfileV3(t)
	if p.SaltSize() != 32 {
		t.Errorf("SaltSize = %d, want 32", p.SaltSize())
	}
	if p.NonceSize() != 12 {
		t.Errorf("NonceSize = %d, want 12", p.NonceSize())
	}
}

func TestProfileV3KEMName(t *testing.T) {
	if testProfileV3(t).KEMName() == "" {
		t.Error("ProfileV3.KEMName() is empty")
	}
}

func TestProfileV3DeriveKey(t *testing.T) {
	// Use the registered instance (has proper argon2 parameters).
	p, err := GetProfile(3, nil)
	if err != nil {
		t.Fatalf("GetProfile(3): %v", err)
	}
	salt := make([]byte, p.SaltSize())
	k1 := p.DeriveKey([]byte("pass"), salt)
	k2 := p.DeriveKey([]byte("pass"), salt)
	if !bytes.Equal(k1, k2) {
		t.Error("ProfileV3.DeriveKey is not deterministic")
	}
	if len(k1) != 32 {
		t.Errorf("key length = %d, want 32", len(k1))
	}
}

func TestProfileV3NewAEAD(t *testing.T) {
	p, err := GetProfile(3, nil)
	if err != nil {
		t.Fatalf("GetProfile(3): %v", err)
	}
	salt := make([]byte, p.SaltSize())
	key := p.DeriveKey([]byte("pass"), salt)
	aead, err := p.NewAEAD(key)
	if err != nil {
		t.Fatalf("ProfileV3.NewAEAD: %v", err)
	}
	if aead == nil {
		t.Error("ProfileV3.NewAEAD returned nil")
	}
}

func TestProfileV3GenerateHybridKeyPair(t *testing.T) {
	if testing.Short() {
		t.Skip("FrodoKEM-640 key generation is slow; skipped in -short mode")
	}
	p := testProfileV3(t)
	priv, pub, err := p.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("ProfileV3.GenerateHybridKeyPair: %v", err)
	}
	if len(priv) == 0 || len(pub) == 0 {
		t.Error("GenerateHybridKeyPair returned empty key")
	}
	SafeClear(priv)
}

func TestProfileV3RecipientBlockSize(t *testing.T) {
	p := testProfileV3(t)
	if p.RecipientBlockSize() <= 0 {
		t.Errorf("RecipientBlockSize = %d, want > 0", p.RecipientBlockSize())
	}
}

func TestProfileV3EncryptDecryptRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("FrodoKEM-640 KEM is slow; skipped in -short mode")
	}
	p := testProfileV3(t)
	priv, pub, err := p.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	defer SafeClear(priv)

	plaintext := []byte("profile v3 conservative encrypt round-trip")
	var ct bytes.Buffer
	if err := EncryptStreamWithPublicKeys(bytes.NewReader(plaintext), &ct, [][]byte{pub}, FlagNone, 1, p.ID()); err != nil {
		t.Fatalf("encrypt with ProfileV3: %v", err)
	}

	var out bytes.Buffer
	if _, _, err := DecryptStreamWithPrivateKey(bytes.NewReader(ct.Bytes()), &out, priv, nil, 1, false); err != nil {
		t.Fatalf("decrypt with ProfileV3: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Error("ProfileV3 round-trip mismatch")
	}
}

// --- DynamicProfile ---

func TestDynamicProfileGenerateRandom(t *testing.T) {
	dp := GenerateRandomProfile(201)
	if dp == nil {
		t.Fatal("GenerateRandomProfile returned nil")
	}
	if dp.ID() != 201 {
		t.Errorf("ID = %d, want 201", dp.ID())
	}
	if dp.SaltSize() <= 0 {
		t.Error("SaltSize <= 0")
	}
}

func TestDynamicProfileValidate(t *testing.T) {
	dp := GenerateRandomProfile(202)
	if err := dp.Validate(); err != nil {
		t.Errorf("GenerateRandomProfile should produce valid profile: %v", err)
	}
}

func TestDynamicProfileValidateInvalid(t *testing.T) {
	dp := &DynamicProfile{CustomID: 203} // missing fields → invalid
	err := dp.Validate()
	if err == nil {
		t.Error("empty DynamicProfile should fail Validate")
	}
}

func TestDynamicProfilePackUnpack(t *testing.T) {
	dp := GenerateRandomProfile(204)
	packed := dp.Pack()
	if len(packed) == 0 {
		t.Fatal("Pack returned empty bytes")
	}

	unpacked, err := UnpackDynamicProfile(dp.ID(), packed)
	if err != nil {
		t.Fatalf("UnpackDynamicProfile: %v", err)
	}
	if unpacked.ArgonTime != dp.ArgonTime {
		t.Errorf("ArgonTime mismatch after pack/unpack: %d != %d", unpacked.ArgonTime, dp.ArgonTime)
	}
}

func TestDynamicProfileName(t *testing.T) {
	dp := &DynamicProfile{CustomID: 205}
	name := dp.Name()
	if name == "" {
		t.Error("DynamicProfile.Name() returned empty string")
	}
}

func TestDynamicProfileDeriveKey(t *testing.T) {
	dp := GenerateRandomProfile(206)
	salt := make([]byte, dp.SaltSize())
	k1 := dp.DeriveKey([]byte("pass"), salt)
	k2 := dp.DeriveKey([]byte("pass"), salt)
	if !bytes.Equal(k1, k2) {
		t.Error("DynamicProfile.DeriveKey is not deterministic")
	}
}

func TestDynamicProfileNewAEAD(t *testing.T) {
	dp := GenerateRandomProfile(207)
	salt := make([]byte, dp.SaltSize())
	key := dp.DeriveKey([]byte("pass"), salt)
	aead, err := dp.NewAEAD(key)
	if err != nil {
		t.Fatalf("DynamicProfile.NewAEAD: %v", err)
	}
	if aead == nil {
		t.Error("DynamicProfile.NewAEAD returned nil")
	}
}

func TestLoadCustomProfileFromFile(t *testing.T) {
	dp := GenerateRandomProfile(208)
	data, err := json.Marshal(dp)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	os.WriteFile(path, data, 0600)

	loaded, err := LoadCustomProfile(path)
	if err != nil {
		t.Fatalf("LoadCustomProfile: %v", err)
	}
	if loaded.ID() != dp.ID() {
		t.Errorf("loaded ID = %d, want %d", loaded.ID(), dp.ID())
	}
}

func TestLoadCustomProfileFileMissing(t *testing.T) {
	_, err := LoadCustomProfile("/nonexistent/profile.json")
	if err == nil {
		t.Error("expected error for missing profile file")
	}
}

// --- Engine profile methods ---

func TestEngineGenerateAndValidateRandomProfile(t *testing.T) {
	e := engineForVault(t)

	dp := e.GenerateRandomProfile(nil, 209)
	if dp == nil {
		t.Fatal("Engine.GenerateRandomProfile returned nil")
	}
	if err := e.ValidateProfile(nil, dp); err != nil {
		t.Errorf("Engine.ValidateProfile: %v", err)
	}
}

func TestEngineRegisterAndRemoveProfile(t *testing.T) {
	e := engineForVault(t)

	dp := GenerateRandomProfile(210)
	if err := e.RegisterProfile(nil, "myprofile", dp); err != nil {
		t.Fatalf("Engine.RegisterProfile: %v", err)
	}
	if err := e.RemoveProfile(nil, "myprofile"); err != nil {
		t.Fatalf("Engine.RemoveProfile: %v", err)
	}
}
