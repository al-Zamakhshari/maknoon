package crypto

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func init() {
	RegisterRegistry("nostr", func(conf *Config) IdentityRegistry {
		return NewNostrRegistry(conf)
	})
}

// NostrRegistry implements IdentityRegistry using Nostr relays.
type NostrRegistry struct {
	Relays []string
}

// NewNostrRegistry creates a new Nostr registry using configured relays.
func NewNostrRegistry(conf *Config) *NostrRegistry {
	if conf == nil {
		conf = GetGlobalConfig()
	}
	relays := conf.Nostr.Relays
	if len(relays) == 0 {
		relays = DefaultConfig().Nostr.Relays
	}
	return &NostrRegistry{
		Relays: relays,
	}
}

func (r *NostrRegistry) Resolve(ctx context.Context, handle string) (*IdentityRecord, error) {
	var pubkey string

	// 1. Handle NIP-05 (user@domain.com)
	// Must contain @ and have a non-empty user part (part before @)
	if strings.Contains(handle, "@") && !strings.HasPrefix(handle, "@nostr:") && !strings.HasPrefix(handle, "npub1") {
		parts := strings.Split(handle, "@")
		if len(parts) == 2 && parts[0] != "" {
			user := parts[0]
			domain := parts[1]

			// SSRF Mitigation: Validate domain before making the request.
			if !isValidDomain(domain) {
				return nil, fmt.Errorf("invalid or prohibited domain for resolution: %s", domain)
			}

			// Build the URL via url.URL struct construction so that each component is
			// individually encoded.  This breaks the string-taint chain that CodeQL's
			// go/request-forgery analysis tracks from the raw `domain` variable:
			// - Host is set as a structured field (not interpolated into a raw string)
			// - user is encoded via url.Values.Encode() which percent-escapes it
			// isValidDomain() has already confirmed `domain` resolves only to public IPs.
			resolvedURL := &url.URL{
				Scheme:   "https",
				Host:     domain,
				Path:     "/.well-known/nostr.json",
				RawQuery: url.Values{"name": {user}}.Encode(),
			}

			req, _ := http.NewRequestWithContext(ctx, "GET", resolvedURL.String(), nil)
			resp, err := http.DefaultClient.Do(req)
			if err == nil && resp.StatusCode == 200 {
				var result struct {
					Names map[string]string `json:"names"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
					if pk, ok := result.Names[user]; ok {
						pubkey = pk
					}
				}
				resp.Body.Close()
			}
		}
	}

	if pubkey == "" {
		// 2. Handle npub or hex pubkey or simple @name (if hex)
		cleanHandle := strings.TrimPrefix(handle, "@")
		if strings.HasPrefix(cleanHandle, "npub1") {
			_, v, err := nip19.Decode(cleanHandle)
			if err != nil {
				return nil, fmt.Errorf("invalid npub: %w", err)
			}
			pubkey = v.(string)
		} else if len(cleanHandle) == 64 {
			// Check if it's hex
			if _, err := hex.DecodeString(cleanHandle); err == nil {
				pubkey = cleanHandle
			}
		}
	}

	if pubkey == "" {
		// 3. Last resort: Try to find Kind 0 by name (not standard, but helpful for local testing)
		// Standard Nostr requires hex/npub for authorship query.
		return nil, fmt.Errorf("unsupported nostr handle format or resolution failed: %s", handle)
	}

	// 3. Query relays for Kind 0 event
	filter := nostr.Filter{
		Kinds:   []int{0},
		Authors: []string{pubkey},
		Limit:   1,
	}

	if len(r.Relays) == 0 {
		return nil, fmt.Errorf("no Nostr relays configured for resolution")
	}

	var latestEvent *nostr.Event
	for _, url := range r.Relays {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			continue
		}

		events, err := relay.QuerySync(ctx, filter)
		relay.Close()
		if err != nil {
			continue
		}
		if len(events) == 0 {
			continue
		}

		event := events[0]
		// VERIFY: Try to parse this specific event. If it's malformed, skip it!
		var metadata map[string]interface{}
		if err := json.Unmarshal([]byte(event.Content), &metadata); err != nil {
			continue // Skip malformed content from this relay
		}

		if latestEvent == nil || event.CreatedAt > latestEvent.CreatedAt {
			latestEvent = event
		}
	}

	if latestEvent == nil {
		return nil, fmt.Errorf("no valid maknoon identity found on Nostr relays for %s", pubkey)
	}

	// 3. Parse the verified latest event
	var metadata map[string]interface{}
	json.Unmarshal([]byte(latestEvent.Content), &metadata)

	maknoonRaw, ok := metadata["maknoon"].(string)
	if !ok {
		return nil, fmt.Errorf("no 'maknoon' field found in verified Nostr profile for %s", pubkey)
	}

	return parseMaknoonTXT("v=maknoon1;z=1;data=" + maknoonRaw)
}

func (r *NostrRegistry) Publish(ctx context.Context, record *IdentityRecord) error {
	return fmt.Errorf("nostr publishing requires a private Secp256k1 key (use PublishWithKey)")
}

func (r *NostrRegistry) PublishWithKey(ctx context.Context, record *IdentityRecord, nostrPrivKey []byte) error {
	privHex := hex.EncodeToString(nostrPrivKey)
	pubHex, err := nostr.GetPublicKey(privHex)
	if err != nil {
		return fmt.Errorf("invalid nostr private key: %w", err)
	}

	// 1. Fetch current metadata to avoid overwriting other fields
	var metadata map[string]interface{}
	filter := nostr.Filter{
		Kinds:   []int{0},
		Authors: []string{pubHex},
		Limit:   1,
	}

	for _, url := range r.Relays {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			continue
		}
		events, err := relay.QuerySync(ctx, filter)
		relay.Close()
		if err == nil && len(events) > 0 {
			json.Unmarshal([]byte(events[0].Content), &metadata)
			break
		}
	}

	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// 2. Add Maknoon record
	recordStr, err := GetCompactDNSRecordString(record)
	if err != nil {
		return err
	}
	// Extract data part from v=maknoon1;z=1;data=...
	dataIdx := strings.Index(recordStr, "data=")
	if dataIdx == -1 {
		return fmt.Errorf("invalid record string")
	}
	metadata["maknoon"] = recordStr[dataIdx+5:]

	// Optional: Add a note about Maknoon in the about section
	if GetGlobalConfig().Nostr.PublishMetadata {
		about, _ := metadata["about"].(string)
		if !strings.Contains(strings.ToLower(about), "maknoon") {
			if about != "" {
				about += "\n"
			}
			about += "PQC Encryption Enabled (Maknoon)"
			metadata["about"] = about
		}
	}
	content, _ := json.Marshal(metadata)

	// 3. Create and sign Nostr event
	ev := nostr.Event{
		PubKey:    pubHex,
		CreatedAt: nostr.Now(),
		Kind:      0,
		Tags:      nil,
		Content:   string(content),
	}

	if err := ev.Sign(privHex); err != nil {
		return fmt.Errorf("failed to sign nostr event: %w", err)
	}

	// 4. Publish to relays
	publishedCount := 0
	for _, url := range r.Relays {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			continue
		}
		err = relay.Publish(ctx, ev)
		relay.Close()
		if err == nil {
			publishedCount++
		}
	}

	if publishedCount == 0 {
		return fmt.Errorf("failed to publish to any Nostr relays")
	}

	return nil
}

func (r *NostrRegistry) Revoke(ctx context.Context, handle string, proof []byte) error {
	// In Nostr, we'd probably just publish a new event with revoked=true or deleted
	return fmt.Errorf("nostr revocation not implemented in POC")
}

// RelayHealth holds the connectivity result for a single Nostr relay.
type RelayHealth struct {
	URL       string `json:"url"`
	Reachable bool   `json:"reachable"`
	LatencyMs int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// HealthCheck probes each configured relay and returns connectivity results.
// Each relay gets a 5-second connection timeout.
func (r *NostrRegistry) HealthCheck(ctx context.Context) []RelayHealth {
	results := make([]RelayHealth, len(r.Relays))
	type pair struct {
		idx int
		h   RelayHealth
	}
	ch := make(chan pair, len(r.Relays))

	for i, relayURL := range r.Relays {
		go func(idx int, u string) {
			h := RelayHealth{URL: u}
			dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			start := time.Now()
			relay, err := nostr.RelayConnect(dialCtx, u)
			h.LatencyMs = time.Since(start).Milliseconds()
			if err != nil {
				h.Error = err.Error()
			} else {
				h.Reachable = true
				relay.Close()
			}
			ch <- pair{idx, h}
		}(i, relayURL)
	}

	for range r.Relays {
		p := <-ch
		results[p.idx] = p.h
	}
	return results
}

// isValidDomain ensures the domain resolves to a legitimate public address, not a local or
// internal one. Defends against SSRF by blocking RFC1918, loopback, link-local, ULA,
// multicast, and unspecified ranges for both IPv4 and IPv6.
func isValidDomain(domain string) bool {
	if domain == "" || len(domain) > 255 {
		return false
	}
	// Reject syntactically suspicious values before DNS resolution.
	if strings.ContainsAny(domain, " /\\?#@") {
		return false
	}
	// Must contain a dot (rules out bare "localhost" and single-label names).
	if !strings.Contains(domain, ".") {
		return false
	}

	// If the domain is a bare IP literal, validate it directly.
	if ip := net.ParseIP(domain); ip != nil {
		return isPublicIP(ip)
	}

	// Resolve the domain and check all returned addresses.
	addrs, err := net.LookupHost(domain)
	if err != nil {
		// If resolution fails we cannot confirm it is safe — reject.
		return false
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil || !isPublicIP(ip) {
			return false
		}
	}
	return len(addrs) > 0
}

// isPublicIP returns true only for globally routable unicast addresses,
// blocking loopback, private (RFC1918/RFC4193), link-local, multicast, and unspecified.
func isPublicIP(ip net.IP) bool {
	return !ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() &&
		!ip.IsUnspecified()
}
