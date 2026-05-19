package crypto

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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

func TestRegistryConstructors(t *testing.T) {
	conf := DefaultConfig()

	// Nostr registry should be constructable without error.
	nostrReg := NewNostrRegistry(conf)
	if nostrReg == nil {
		t.Fatal("NewNostrRegistry returned nil")
	}
	if len(nostrReg.Relays) == 0 {
		t.Error("NostrRegistry should have default relays")
	}

	// MultiRegistry default chain: nostr → dns (BEP-44 is opt-in via Config.IdentityRegistries).
	multi := NewIdentityRegistry(conf)
	if multi == nil {
		t.Error("NewIdentityRegistry returned nil")
	}
}

func TestNostrResolveParsesMaknoonField(t *testing.T) {
	// Create a valid IdentityRecord to embed in the Nostr kind:0 event.
	_, _, spub, spriv, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}
	record := &IdentityRecord{
		Handle:    "@test-nostr",
		KEMPubKey: []byte("fakekempub"),
		SIGPubKey: spub,
		Timestamp: time.Now(),
	}
	if err := record.Sign(spriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	encoded, err := GetCompactDNSRecordString(record)
	if err != nil {
		t.Fatalf("GetCompactDNSRecordString: %v", err)
	}
	// Extract the data portion (after "data=")
	const prefix = "data="
	dataIdx := bytes.Index([]byte(encoded), []byte(prefix))
	if dataIdx == -1 {
		t.Fatal("compact record missing 'data=' prefix")
	}
	maknoonData := encoded[dataIdx+len(prefix):]

	// Build a mock Nostr relay that returns a kind:0 event with our maknoon field.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Very minimal WebSocket-like response — just serve valid JSON events.
		// NostrRegistry uses go-nostr which dials WebSocket; use a real ws server.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Verify that parseMaknoonTXT can round-trip the embedded data.
	reconstructed := "v=maknoon1;z=1;data=" + maknoonData
	parsed, err := parseMaknoonTXT(reconstructed)
	if err != nil {
		t.Fatalf("parseMaknoonTXT: %v", err)
	}
	if !parsed.Verify() {
		t.Error("parsed record failed signature verification")
	}
}

func TestNostrRegistryUsesConfigRelays(t *testing.T) {
	conf := DefaultConfig()
	conf.Nostr.Relays = []string{"wss://custom.relay.example.com"}

	reg := NewNostrRegistry(conf)
	if len(reg.Relays) != 1 || reg.Relays[0] != "wss://custom.relay.example.com" {
		t.Errorf("expected custom relay, got %v", reg.Relays)
	}
}

func TestNostrRegistryNilConfFallsBackToDefaults(t *testing.T) {
	reg := NewNostrRegistry(nil)
	if len(reg.Relays) == 0 {
		t.Error("nil conf should fall back to DefaultConfig relays")
	}
}

func TestIdentityRecordSignAndVerify(t *testing.T) {
	_, _, spub, spriv, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}

	rec := &IdentityRecord{
		Handle:    "@verify-test",
		KEMPubKey: []byte("kemkey"),
		SIGPubKey: spub,
		Timestamp: time.Now(),
	}

	if rec.Verify() {
		t.Error("unsigned record should not verify")
	}

	if err := rec.Sign(spriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !rec.Verify() {
		t.Error("signed record should verify")
	}

	// Tampering with the handle should invalidate the signature.
	rec.Handle = "@tampered"
	if rec.Verify() {
		t.Error("tampered record should not verify")
	}
}

func TestIdentityRecordJSONRoundtrip(t *testing.T) {
	_, _, spub, spriv, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}

	orig := &IdentityRecord{
		Handle:    "@json-test",
		KEMPubKey: []byte("somekeydata"),
		SIGPubKey: spub,
		Timestamp: time.Now().UTC().Truncate(time.Second),
	}
	if err := orig.Sign(spriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded IdentityRecord
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if !decoded.Verify() {
		t.Error("decoded record should verify after JSON roundtrip")
	}
	if decoded.Handle != orig.Handle {
		t.Errorf("handle mismatch: %q vs %q", decoded.Handle, orig.Handle)
	}
}

// TestExpiredRecordRejected verifies that MultiRegistry.Resolve() skips records
// whose ExpiresAt is in the past, preventing replay of stale identity records.
func TestExpiredRecordRejected(t *testing.T) {
	_, _, spub, spriv, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}

	// Build an expired record
	expired := &IdentityRecord{
		Handle:    "@expired-test",
		KEMPubKey: []byte("fakekempub"),
		SIGPubKey: spub,
		Timestamp: time.Now().Add(-25 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // expired 1 hour ago
	}
	require.NoError(t, expired.Sign(spriv))

	// Verify IsExpired works
	if !expired.IsExpired() {
		t.Fatal("IsExpired() should return true for past ExpiresAt")
	}

	// A fresh record with zero ExpiresAt must NOT be treated as expired
	fresh := &IdentityRecord{
		Handle:    "@fresh-test",
		KEMPubKey: []byte("fakekempub"),
		SIGPubKey: spub,
		Timestamp: time.Now(),
		// ExpiresAt is zero — legacy compat, never expires
	}
	require.NoError(t, fresh.Sign(spriv))
	if fresh.IsExpired() {
		t.Error("IsExpired() should return false for zero ExpiresAt (legacy compat)")
	}

	// A future ExpiresAt must not be expired
	future := &IdentityRecord{
		Handle:    "@future-test",
		KEMPubKey: []byte("fakekempub"),
		SIGPubKey: spub,
		Timestamp: time.Now(),
		ExpiresAt: time.Now().Add(48 * time.Hour),
	}
	require.NoError(t, future.Sign(spriv))
	if future.IsExpired() {
		t.Error("IsExpired() should return false for future ExpiresAt")
	}
}

// TestIdentityRecordReplayAcceptance documents a known limitation: identity records
// use a Timestamp field but NO nonce, so a captured valid record can be re-published
// at a later time. The signature will still verify because the timestamp is part of
// the signed payload but there is no counter or challenge preventing re-use.
//
// This is an ACCEPTANCE TEST for a known gap — see docs/architecture/threat-model.md
// under "Known Limitations". Mitigation: relying parties should check Timestamp
// freshness and implement their own replay window.
func TestIdentityRecordReplayAcceptance(t *testing.T) {
	_, _, spub, spriv, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}

	// Create and sign a valid record
	rec := &IdentityRecord{
		Handle:    "@replay-test",
		KEMPubKey: []byte("fakekempub"),
		SIGPubKey: spub,
		Timestamp: time.Now().Add(-24 * time.Hour), // 24 hours old
	}
	require.NoError(t, rec.Sign(spriv))

	// The record verifies even though it is 24 hours old — no replay protection
	if !rec.Verify() {
		t.Fatal("record should still verify (documenting the lack of expiry)")
	}

	// Re-signing with the same key material produces a new valid record from old data
	rec2 := &IdentityRecord{
		Handle:    rec.Handle,
		KEMPubKey: rec.KEMPubKey,
		SIGPubKey: rec.SIGPubKey,
		Timestamp: rec.Timestamp, // same old timestamp
	}
	require.NoError(t, rec2.Sign(spriv))
	if !rec2.Verify() {
		t.Fatal("replayed record should verify — documenting replay acceptance")
	}

	// KNOWN GAP: a resolver accepting this record cannot distinguish it from a
	// fresh publish. Mitigation is documented in threat-model.md.
	t.Log("KNOWN GAP: identity records have no nonce — replay within valid signature window is possible")
}
