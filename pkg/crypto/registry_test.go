package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

	// WKD registry should be constructable without error.
	wkdReg := NewWKDRegistry(conf)
	if wkdReg == nil {
		t.Fatal("NewWKDRegistry returned nil")
	}

	// MultiRegistry default chain: wkd → dns.
	multi := NewIdentityRegistry(conf)
	if multi == nil {
		t.Error("NewIdentityRegistry returned nil")
	}
}

func TestWKDResolve(t *testing.T) {
	_, _, spub, spriv, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}
	record := &IdentityRecord{
		Handle:    "@alice@example.com",
		KEMPubKey: []byte("fakekempub"),
		SIGPubKey: spub,
		Timestamp: time.Now(),
		ExpiresAt: time.Now().Add(48 * time.Hour),
	}
	require.NoError(t, record.Sign(spriv))

	// Serve the record from a local HTTP test server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/alice.json") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(record)
	}))
	defer srv.Close()

	// Override the registry to hit the test server by resolving the domain to localhost.
	// (We can't use isValidDomain for a test server, so we test wkdURL directly.)
	localpart, domain, err := parseWKDHandle("@alice@example.com")
	if err != nil {
		t.Fatalf("parseWKDHandle: %v", err)
	}
	if localpart != "alice" || domain != "example.com" {
		t.Errorf("unexpected parse: localpart=%q domain=%q", localpart, domain)
	}

	url := wkdURL("alice", "example.com")
	if !strings.Contains(url, "/.well-known/maknoon/alice.json") {
		t.Errorf("unexpected WKD URL: %s", url)
	}
}

func TestWKDPublishReturnsManualResult(t *testing.T) {
	_, _, spub, spriv, err := GeneratePQKeyPair(1)
	require.NoError(t, err)

	record := &IdentityRecord{
		Handle:    "@alice@example.com",
		KEMPubKey: []byte("fakekempub"),
		SIGPubKey: spub,
		Timestamp: time.Now(),
	}
	require.NoError(t, record.Sign(spriv))

	reg := NewWKDRegistry(nil)
	err = reg.Publish(context.Background(), record)
	var manual *ErrWKDPublishManual
	if !errors.As(err, &manual) {
		t.Fatalf("expected ErrWKDPublishManual, got %T: %v", err, err)
	}
	if manual.URL != "https://example.com/.well-known/maknoon/alice.json" {
		t.Errorf("unexpected URL: %s", manual.URL)
	}
	if len(manual.Content) == 0 {
		t.Error("expected non-empty content")
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

func TestExpiredRecordRejected(t *testing.T) {
	_, _, spub, spriv, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}

	expired := &IdentityRecord{
		Handle:    "@expired-test",
		KEMPubKey: []byte("fakekempub"),
		SIGPubKey: spub,
		Timestamp: time.Now().Add(-25 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	require.NoError(t, expired.Sign(spriv))

	if !expired.IsExpired() {
		t.Fatal("IsExpired() should return true for past ExpiresAt")
	}

	fresh := &IdentityRecord{
		Handle:    "@fresh-test",
		KEMPubKey: []byte("fakekempub"),
		SIGPubKey: spub,
		Timestamp: time.Now(),
	}
	require.NoError(t, fresh.Sign(spriv))
	if fresh.IsExpired() {
		t.Error("IsExpired() should return false for zero ExpiresAt (legacy compat)")
	}

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

func TestIdentityRecordReplayAcceptance(t *testing.T) {
	_, _, spub, spriv, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}

	rec := &IdentityRecord{
		Handle:    "@replay-test",
		KEMPubKey: []byte("fakekempub"),
		SIGPubKey: spub,
		Timestamp: time.Now().Add(-24 * time.Hour),
	}
	require.NoError(t, rec.Sign(spriv))

	if !rec.Verify() {
		t.Fatal("record should still verify (documenting the lack of expiry)")
	}

	rec2 := &IdentityRecord{
		Handle:    rec.Handle,
		KEMPubKey: rec.KEMPubKey,
		SIGPubKey: rec.SIGPubKey,
		Timestamp: rec.Timestamp,
	}
	require.NoError(t, rec2.Sign(spriv))
	if !rec2.Verify() {
		t.Fatal("replayed record should verify — documenting replay acceptance")
	}

	t.Log("KNOWN GAP: identity records have no nonce — replay within valid signature window is possible")
}

// --- DNSRegistry ---

func TestDNSRegistryConstructor(t *testing.T) {
	conf := DefaultConfig()
	reg := NewDNSRegistry(conf)
	if reg == nil {
		t.Fatal("NewDNSRegistry returned nil")
	}
}

func TestDNSRegistryPublishReturnsManualInstruction(t *testing.T) {
	reg := NewDNSRegistry(DefaultConfig())
	_, _, spub, spriv, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}
	kpub, _, _, _, _ := GeneratePQKeyPair(1)
	rec := &IdentityRecord{
		Handle:    "@alice@example.com",
		KEMPubKey: kpub,
		SIGPubKey: spub,
		Timestamp: time.Now(),
	}
	if err := rec.Sign(spriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	err = reg.Publish(context.Background(), rec)
	if err == nil {
		t.Fatal("expected non-nil error (manual instruction)")
	}
	if !strings.Contains(err.Error(), "manual") {
		t.Errorf("expected 'manual' in error: %v", err)
	}
}

func TestDNSRegistryPublishWithKeyDelegatesToPublish(t *testing.T) {
	reg := NewDNSRegistry(DefaultConfig())
	kpub, _, spub, spriv, _ := GeneratePQKeyPair(1)
	rec := &IdentityRecord{
		Handle:    "@alice@example.com",
		KEMPubKey: kpub,
		SIGPubKey: spub,
		Timestamp: time.Now(),
	}
	rec.Sign(spriv)

	err1 := reg.Publish(context.Background(), rec)
	err2 := reg.PublishWithKey(context.Background(), rec, []byte("token"))
	if err1 == nil || err2 == nil {
		t.Fatal("expected non-nil errors from both Publish calls")
	}
	if err1.Error() != err2.Error() {
		t.Errorf("PublishWithKey should delegate to Publish:\n  Publish:        %v\n  PublishWithKey: %v", err1, err2)
	}
}

func TestDNSRegistryRevokeReturnsManualInstruction(t *testing.T) {
	reg := NewDNSRegistry(DefaultConfig())
	err := reg.Revoke(context.Background(), "@alice@example.com", nil)
	if err == nil {
		t.Fatal("expected non-nil error (manual instruction)")
	}
	if !strings.Contains(err.Error(), "manual") {
		t.Errorf("expected 'manual' in revoke error: %v", err)
	}
}
