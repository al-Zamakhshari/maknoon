package crypto

import (
	"bytes"
	"testing"
	"time"
)

func TestIdentityRecordSerializationRoundtrip(t *testing.T) {
	kpub, kpriv, spub, spriv, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair failed: %v", err)
	}
	defer SafeClear(kpriv)
	defer SafeClear(spriv)

	record := &IdentityRecord{
		Handle:    "@alice",
		KEMPubKey: kpub,
		SIGPubKey: spub,
		Timestamp: time.Now(),
	}
	if err := record.Sign(spriv); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify compact (zstd-compressed) serialization round-trips correctly.
	encoded, err := GetCompactDNSRecordString(record)
	if err != nil {
		t.Fatalf("GetCompactDNSRecordString failed: %v", err)
	}

	parsed, err := parseMaknoonTXT(encoded)
	if err != nil {
		t.Fatalf("parseMaknoonTXT failed: %v", err)
	}

	if !bytes.Equal(parsed.KEMPubKey, record.KEMPubKey) {
		t.Error("KEM public key mismatch after roundtrip")
	}
	if !parsed.Verify() {
		t.Error("Parsed record failed ML-DSA signature verification")
	}
}

func TestBEP44HandleExtraction(t *testing.T) {
	_, _, spub, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair failed: %v", err)
	}

	handle, err := BEP44HandleFromSIGPub(spub)
	if err != nil {
		t.Fatalf("BEP44HandleFromSIGPub failed: %v", err)
	}

	if !IsBEP44Handle(handle) {
		t.Errorf("expected IsBEP44Handle true, got false for %s", handle)
	}

	pubKey, err := extractEd25519PubFromHandle(handle)
	if err != nil {
		t.Fatalf("extractEd25519PubFromHandle failed: %v", err)
	}

	// Re-derive from the SIG pub and verify they match.
	expectedHandle, _ := BEP44HandleFromSIGPub(spub)
	if handle != expectedHandle {
		t.Errorf("handle mismatch: got %s want %s", handle, expectedHandle)
	}
	_ = pubKey
}
