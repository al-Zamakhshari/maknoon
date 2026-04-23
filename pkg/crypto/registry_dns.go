package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

func init() {
	RegisterRegistry("dns", func() IdentityRegistry {
		return NewDNSRegistry()
	})
}

// DNSRegistry implements IdentityRegistry by resolving keys from DNS TXT records.
type DNSRegistry struct {
	resolver *net.Resolver
}

func NewDNSRegistry() *DNSRegistry {
	return &DNSRegistry{resolver: net.DefaultResolver}
}

func (r *DNSRegistry) Resolve(ctx context.Context, handle string) (*IdentityRecord, error) {
	// Handle should be a domain name (e.g., "alice.com" or "@alice.com")
	domain := strings.TrimPrefix(handle, "@")

	// We look for TXT records at _maknoon.<domain>
	txtRecords, err := r.resolver.LookupTXT(ctx, "_maknoon."+domain)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", domain, err)
	}

	for _, txt := range txtRecords {
		if record, err := parseMaknoonTXT(txt); err == nil {
			return record, nil
		}
	}

	return nil, fmt.Errorf("no valid Maknoon record found in DNS for %s", domain)
}

func (r *DNSRegistry) Publish(ctx context.Context, record *IdentityRecord) error {
	return errors.New("DNS Publish is manual: please add the TXT record to your domain")
}

func (r *DNSRegistry) PublishWithKey(ctx context.Context, record *IdentityRecord, _ []byte) error {
	return r.Publish(ctx, record)
}

func (r *DNSRegistry) Revoke(ctx context.Context, handle string, proof []byte) error {
	return errors.New("DNS Revocation is manual: please remove the TXT record from your domain")
}

// PublishToDesec performs an authenticated request to deSEC.io to create or update the _maknoon TXT record.
func (r *DNSRegistry) PublishToDesec(ctx context.Context, domain string, token string, record *IdentityRecord) error {
	recordStr, err := GetDNSRecordString(record)
	if err != nil {
		return fmt.Errorf("failed to get DNS record string: %w", err)
	}

	// Prepare deSEC API request body. deSEC requires TXT records to be quoted.
	data := map[string]interface{}{
		"subname": "_maknoon",
		"type":    "TXT",
		"records": []string{fmt.Sprintf("\"%s\"", recordStr)},
		"ttl":     3600,
	}
	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal deSEC request body: %w", err)
	}

	// Try PUT first (Update)
	putUrl := fmt.Sprintf("https://desec.io/api/v1/domains/%s/rrsets/_maknoon/TXT/", domain)
	req, err := http.NewRequestWithContext(ctx, "PUT", putUrl, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create deSEC PUT request: %w", err)
	}
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("deSEC API request failed: %w", err)
	}
	defer resp.Body.Close()

	// If 404, the record doesn't exist yet. Try POST (Create)
	if resp.StatusCode == http.StatusNotFound {
		postUrl := fmt.Sprintf("https://desec.io/api/v1/domains/%s/rrsets/", domain)
		req, err = http.NewRequestWithContext(ctx, "POST", postUrl, bytes.NewBuffer(body))
		if err != nil {
			return fmt.Errorf("failed to create deSEC POST request: %w", err)
		}
		req.Header.Set("Authorization", "Token "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("deSEC API POST request failed: %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("deSEC API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}
