package crypto

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockTransport intercepts HTTP requests and serves them locally, allowing
// tests to use fake domains (e.g. "example.com") that pass the SSRF domain
// check while routing all traffic to a test handler.
type mockTransport struct {
	handler http.Handler
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	m.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

// wkdWithMockServer creates a WKDRegistry whose HTTP client routes all
// requests through the provided handler, bypassing actual network calls.
func wkdWithMockServer(h http.Handler) *WKDRegistry {
	return &WKDRegistry{
		client: &http.Client{Transport: &mockTransport{handler: h}},
	}
}

// validRecord generates a signed IdentityRecord for "alice@example.com".
func validRecord(t *testing.T) *IdentityRecord {
	t.Helper()
	kpub, _, spub, spriv, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}
	rec := &IdentityRecord{
		Handle:    "@alice@example.com",
		KEMPubKey: kpub,
		SIGPubKey: spub,
		Timestamp: time.Now(),
	}
	if err := rec.Sign(spriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return rec
}

// --- parseWKDHandle ---

func TestParseWKDHandle(t *testing.T) {
	tests := []struct {
		in         string
		wantLocal  string
		wantDomain string
		wantErr    bool
	}{
		{"alice@example.com", "alice", "example.com", false},
		{"@alice@example.com", "alice", "example.com", false},
		{"ALICE@EXAMPLE.COM", "ALICE", "EXAMPLE.COM", false},
		{"@alice", "", "", true},  // no domain
		{"alice", "", "", true},   // no @
		{"@", "", "", true},       // empty both sides
		{"@alice@", "", "", true}, // empty domain
	}
	for _, tt := range tests {
		local, domain, err := parseWKDHandle(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseWKDHandle(%q): expected error, got nil", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseWKDHandle(%q): unexpected error: %v", tt.in, err)
			continue
		}
		if local != tt.wantLocal || domain != tt.wantDomain {
			t.Errorf("parseWKDHandle(%q) = (%q, %q), want (%q, %q)",
				tt.in, local, domain, tt.wantLocal, tt.wantDomain)
		}
	}
}

// --- wkdURL ---

func TestWKDURL(t *testing.T) {
	got := wkdURL("alice", "example.com")
	want := "https://example.com/.well-known/maknoon/alice.json"
	if got != want {
		t.Errorf("wkdURL = %q, want %q", got, want)
	}
}

func TestWKDURLLowercasesLocalpart(t *testing.T) {
	got := wkdURL("ALICE", "example.com")
	if !strings.Contains(got, "/alice.json") {
		t.Errorf("wkdURL did not lowercase localpart: %q", got)
	}
}

// --- Publish ---

func TestWKDPublishReturnsManualInstruction(t *testing.T) {
	rec := validRecord(t)
	reg := NewWKDRegistry(nil)
	err := reg.Publish(context.Background(), rec)
	if err == nil {
		t.Fatal("Publish should return a non-nil error (ErrWKDPublishManual)")
	}
	var manual *ErrWKDPublishManual
	if !errors.As(err, &manual) {
		t.Fatalf("expected ErrWKDPublishManual, got %T: %v", err, err)
	}
	if manual.URL == "" {
		t.Error("ErrWKDPublishManual.URL is empty")
	}
	if len(manual.Content) == 0 {
		t.Error("ErrWKDPublishManual.Content is empty")
	}
	if manual.Revoke {
		t.Error("Publish should not set Revoke=true")
	}
}

func TestWKDPublishContentIsValidJSON(t *testing.T) {
	rec := validRecord(t)
	reg := NewWKDRegistry(nil)
	err := reg.Publish(context.Background(), rec)

	var manual *ErrWKDPublishManual
	errors.As(err, &manual)

	var parsed IdentityRecord
	if jsonErr := json.Unmarshal(manual.Content, &parsed); jsonErr != nil {
		t.Errorf("Publish content is not valid JSON: %v", jsonErr)
	}
}

// --- Revoke ---

func TestWKDRevokeReturnsManualInstruction(t *testing.T) {
	reg := NewWKDRegistry(nil)
	err := reg.Revoke(context.Background(), "@alice@example.com", nil)
	if err == nil {
		t.Fatal("Revoke should return a non-nil error")
	}
	var manual *ErrWKDPublishManual
	if !errors.As(err, &manual) {
		t.Fatalf("expected ErrWKDPublishManual, got %T", err)
	}
	if !manual.Revoke {
		t.Error("Revoke should set Revoke=true")
	}
	if manual.URL == "" {
		t.Error("ErrWKDPublishManual.URL is empty")
	}
}

// --- ErrWKDPublishManual.Error() ---

func TestErrWKDPublishManualErrorString(t *testing.T) {
	publish := &ErrWKDPublishManual{URL: "https://example.com/key.json", Revoke: false}
	if !strings.Contains(publish.Error(), "https://example.com/key.json") {
		t.Errorf("Publish error string missing URL: %s", publish.Error())
	}

	revoke := &ErrWKDPublishManual{URL: "https://example.com/key.json", Revoke: true}
	if !strings.Contains(revoke.Error(), "delete") {
		t.Errorf("Revoke error string should mention 'delete': %s", revoke.Error())
	}
}

// --- Resolve HTTP paths ---

func TestWKDResolveSSRFBlocked(t *testing.T) {
	reg := NewWKDRegistry(nil)
	// 127.0.0.1 is a loopback IP — SSRF guard must block it.
	_, err := reg.Resolve(context.Background(), "@alice@127.0.0.1")
	if err == nil {
		t.Error("expected SSRF guard to block resolve to loopback address")
	}
}

func TestWKDResolveInvalidHandle(t *testing.T) {
	reg := NewWKDRegistry(nil)
	_, err := reg.Resolve(context.Background(), "@alice") // no domain
	if err == nil {
		t.Error("expected error for handle without domain")
	}
}

func TestWKDResolve404(t *testing.T) {
	reg := wkdWithMockServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	// Use a real public IP as domain so isValidDomain passes; the mock intercepts the request.
	_, err := reg.Resolve(context.Background(), "@alice@1.1.1.1")
	if err == nil {
		t.Error("expected error for 404 response")
	}
	if !strings.Contains(err.Error(), "no key published") {
		t.Errorf("unexpected error message for 404: %v", err)
	}
}

func TestWKDResolveNonOKStatus(t *testing.T) {
	reg := wkdWithMockServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	_, err := reg.Resolve(context.Background(), "@alice@1.1.1.1")
	if err == nil {
		t.Error("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code: %v", err)
	}
}

func TestWKDResolveMalformedJSON(t *testing.T) {
	reg := wkdWithMockServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{not valid json"))
	}))
	_, err := reg.Resolve(context.Background(), "@alice@1.1.1.1")
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("error should mention invalid JSON: %v", err)
	}
}

func TestWKDResolveSuccess(t *testing.T) {
	rec := validRecord(t)
	body, _ := json.Marshal(rec)

	reg := wkdWithMockServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	got, err := reg.Resolve(context.Background(), "@alice@1.1.1.1")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if got == nil {
		t.Fatal("Resolve returned nil record")
	}
	if got.Handle != rec.Handle {
		t.Errorf("Handle = %q, want %q", got.Handle, rec.Handle)
	}
}
