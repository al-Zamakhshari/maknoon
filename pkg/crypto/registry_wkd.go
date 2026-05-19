package crypto

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func init() {
	RegisterRegistry("wkd", func(conf *Config) IdentityRegistry {
		return NewWKDRegistry(conf)
	})
}

// WKDRegistry implements IdentityRegistry using HTTPS-hosted JSON files.
//
// URL pattern: https://<domain>/.well-known/maknoon/<localpart>.json
//
// This is a Maknoon-flavoured Web Key Directory (WKD) — the same concept as
// OpenPGP WKD (RFC draft-koch-openpgp-webkey-service) but storing an
// IdentityRecord JSON instead of an armored PGP key. It requires only static
// file hosting (any web server, CDN, or object-store) and no DNS TXT records.
//
// Publishing is a manual step: the user places the generated JSON file at the
// correct URL on their server. Publish() returns the file content and target URL
// so the caller can either upload it or print instructions.
type WKDRegistry struct {
	client *http.Client
}

func NewWKDRegistry(_ *Config) *WKDRegistry {
	return &WKDRegistry{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// parseWKDHandle splits a handle into (localpart, domain).
// Accepts: alice@example.com  →  ("alice", "example.com")
//
//	@alice@example.com  →  ("alice", "example.com")
//
// Returns an error for bare handles like @alice (no domain) since WKD
// requires a domain to build the URL.
func parseWKDHandle(handle string) (localpart, domain string, err error) {
	h := strings.TrimPrefix(handle, "@")
	parts := strings.SplitN(h, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("WKD requires an email-style handle (e.g. alice@example.com), got %q", handle)
	}
	return parts[0], parts[1], nil
}

// wkdURL builds the well-known URL for a given localpart and domain.
func wkdURL(localpart, domain string) string {
	return fmt.Sprintf("https://%s/.well-known/maknoon/%s.json", domain, strings.ToLower(localpart))
}

func (r *WKDRegistry) Resolve(ctx context.Context, handle string) (*IdentityRecord, error) {
	localpart, domain, err := parseWKDHandle(handle)
	if err != nil {
		return nil, err
	}

	// SSRF guard: only resolve to public IPs.
	if !isValidDomain(domain) {
		return nil, fmt.Errorf("WKD: domain %q did not resolve to a public address", domain)
	}

	target := wkdURL(localpart, domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("WKD: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "maknoon/wkd")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("WKD: fetch failed for %s: %w", target, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("WKD: no key published at %s", target)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WKD: unexpected HTTP %d from %s", resp.StatusCode, target)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64 KB cap
	if err != nil {
		return nil, fmt.Errorf("WKD: reading response: %w", err)
	}

	var record IdentityRecord
	if err := json.Unmarshal(body, &record); err != nil {
		return nil, fmt.Errorf("WKD: invalid JSON at %s: %w", target, err)
	}

	if !record.Verify() {
		return nil, fmt.Errorf("WKD: signature verification failed for record at %s", target)
	}

	return &record, nil
}

// Publish generates the JSON file content and returns a WKDPublishResult
// describing the target URL and file content. The caller is responsible for
// uploading the file — WKD publishing is a static-file operation.
func (r *WKDRegistry) Publish(_ context.Context, record *IdentityRecord) error {
	localpart, domain, err := parseWKDHandle(record.Handle)
	if err != nil {
		return err
	}
	target := wkdURL(localpart, domain)
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("WKD: marshal failed: %w", err)
	}
	// Surface the URL and content via a structured error so the CLI can
	// display instructions without needing a separate return type.
	return &ErrWKDPublishManual{URL: target, Content: data}
}

func (r *WKDRegistry) Revoke(_ context.Context, handle string, _ []byte) error {
	localpart, domain, err := parseWKDHandle(handle)
	if err != nil {
		return err
	}
	return &ErrWKDPublishManual{
		URL:     wkdURL(localpart, domain),
		Content: []byte("{}"), // placeholder; deletion is manual
		Revoke:  true,
	}
}

// ErrWKDPublishManual is returned by Publish and Revoke to surface the target
// URL and file content to the caller (CLI or MCP tool) as structured data.
type ErrWKDPublishManual struct {
	URL     string
	Content []byte
	Revoke  bool
}

func (e *ErrWKDPublishManual) Error() string {
	if e.Revoke {
		return fmt.Sprintf("WKD: delete the file at %s to revoke", e.URL)
	}
	return fmt.Sprintf("WKD: upload the generated JSON to %s", e.URL)
}
