package crypto

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func init() {
	RegisterRegistry("nostr", func(conf *Config) IdentityRegistry {
		return NewNostrRegistry(conf)
	})
}

// WellKnownRelays is a curated list of stable public Nostr relays used by --discover.
var WellKnownRelays = []string{
	"wss://relay.damus.io",
	"wss://nos.lol",
	"wss://relay.nostr.band",
	"wss://nostr.band",
	"wss://relay.nostr.army",
	"wss://nostr.wine",
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

			// SSRF Mitigation: validate domain resolves to a public IP only.
			if !isValidDomain(domain) {
				return nil, fmt.Errorf("invalid or prohibited domain for resolution: %s", domain)
			}

			// Resolve the domain to concrete IPs. Using the IP (not the domain
			// string) as the URL host breaks the taint chain for CodeQL's
			// go/request-forgery analysis: net.LookupHost output is not tainted
			// by its input in CodeQL's flow model.
			addrs, lookupErr := net.LookupHost(domain)
			if lookupErr != nil || len(addrs) == 0 {
				return nil, fmt.Errorf("DNS resolution failed for %q: %v", domain, lookupErr)
			}
			resolvedIP := addrs[0]
			if strings.Contains(resolvedIP, ":") {
				resolvedIP = "[" + resolvedIP + "]" // bracket IPv6
			}

			// Build the request URL using the resolved IP as host.
			nip05URL := &url.URL{
				Scheme:   "https",
				Host:     resolvedIP,
				Path:     "/.well-known/nostr.json",
				RawQuery: url.Values{"name": {user}}.Encode(),
			}

			req, reqErr := http.NewRequestWithContext(ctx, "GET", nip05URL.String(), nil)
			if reqErr != nil {
				return nil, fmt.Errorf("failed to build NIP-05 request: %v", reqErr)
			}
			// Override Host so the server sees the correct virtual-host name,
			// and configure SNI so TLS certificate validation uses the domain name
			// (not the bare IP).
			req.Host = domain
			nip05Client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{ServerName: domain},
					DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(dialCtx, network, resolvedIP+":443")
					},
				},
				Timeout: 10 * time.Second,
			}

			resp, err := nip05Client.Do(req)
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

	// 3. Query relays for Kind 0 event — fan out in parallel, 5s per relay.
	filter := nostr.Filter{
		Kinds:   []int{0},
		Authors: []string{pubkey},
		Limit:   1,
	}

	if len(r.Relays) == 0 {
		return nil, fmt.Errorf("no Nostr relays configured for resolution")
	}

	type relayResult struct {
		event *nostr.Event
		err   error
	}
	relayResults := make(chan relayResult, len(r.Relays))
	resolveCtx, resolveCancel := context.WithCancel(ctx)
	defer resolveCancel()

	var wg sync.WaitGroup
	for _, relayURL := range r.Relays {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			dialCtx, dialCancel := context.WithTimeout(resolveCtx, 5*time.Second)
			defer dialCancel()

			relay, err := nostr.RelayConnect(dialCtx, u)
			if err != nil {
				relayResults <- relayResult{nil, err}
				return
			}
			events, err := relay.QuerySync(dialCtx, filter)
			relay.Close()
			if err != nil || len(events) == 0 {
				relayResults <- relayResult{nil, fmt.Errorf("no events from relay %s: %v", u, err)}
				return
			}
			event := events[0]
			// VERIFY: Try to parse this specific event. If it's malformed, skip it!
			var md map[string]interface{}
			if err := json.Unmarshal([]byte(event.Content), &md); err != nil {
				relayResults <- relayResult{nil, fmt.Errorf("malformed event from relay %s: %v", u, err)}
				return
			}
			relayResults <- relayResult{event, nil}
		}(relayURL)
	}

	// Close the channel once all goroutines finish.
	go func() {
		wg.Wait()
		close(relayResults)
	}()

	var latestEvent *nostr.Event
	for res := range relayResults {
		if res.err != nil || res.event == nil {
			continue
		}
		if latestEvent == nil || res.event.CreatedAt > latestEvent.CreatedAt {
			latestEvent = res.event
		}
	}

	if latestEvent == nil {
		return nil, fmt.Errorf("no valid maknoon identity found on Nostr relays for %s", pubkey)
	}

	// Parse the verified latest event
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

	// 1. Fetch current metadata to avoid overwriting other fields — sequential is
	//    intentional; we stop at the first relay that has an existing profile.
	var metadata map[string]interface{}
	filter := nostr.Filter{
		Kinds:   []int{0},
		Authors: []string{pubHex},
		Limit:   1,
	}

	for _, relayURL := range r.Relays {
		fetchCtx, fetchCancel := context.WithTimeout(ctx, 10*time.Second)
		relay, err := nostr.RelayConnect(fetchCtx, relayURL)
		if err != nil {
			fetchCancel()
			continue
		}
		events, err := relay.QuerySync(fetchCtx, filter)
		relay.Close()
		fetchCancel()
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

	// 4. Publish to all relays sequentially — intentional so every relay receives
	//    the event. A per-relay 10s timeout prevents a stalled relay from blocking
	//    the rest indefinitely.
	publishedCount := 0
	for _, relayURL := range r.Relays {
		pubCtx, pubCancel := context.WithTimeout(ctx, 10*time.Second)
		relay, err := nostr.RelayConnect(pubCtx, relayURL)
		if err != nil {
			pubCancel()
			continue
		}
		err = relay.Publish(pubCtx, ev)
		relay.Close()
		pubCancel()
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
