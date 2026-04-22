package crypto

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// NostrRegistry implements IdentityRegistry using Nostr relays.
type NostrRegistry struct {
	Relays []string
}

// NewNostrRegistry creates a new Nostr registry using configured relays.
func NewNostrRegistry() *NostrRegistry {
	conf := GetGlobalConfig()
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

	// 1. Handle npub or hex pubkey
	if strings.HasPrefix(handle, "npub1") {
		_, v, err := nip19.Decode(handle)
		if err != nil {
			return nil, fmt.Errorf("invalid npub: %w", err)
		}
		pubkey = v.(string)
	} else if strings.HasPrefix(handle, "@nostr:") {
		handle = strings.TrimPrefix(handle, "@nostr:")
		if strings.HasPrefix(handle, "npub1") {
			_, v, err := nip19.Decode(handle)
			if err != nil {
				return nil, fmt.Errorf("invalid npub: %w", err)
			}
			pubkey = v.(string)
		} else {
			pubkey = handle // Assume hex
		}
	} else {
		return nil, fmt.Errorf("unsupported nostr handle format: %s", handle)
	}

	// 2. Query relays for Kind 0 event
	filter := nostr.Filter{
		Kinds:   []int{0},
		Authors: []string{pubkey},
		Limit:   1,
	}

	var latestEvent *nostr.Event
	for _, url := range r.Relays {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			continue
		}

		events, err := relay.QuerySync(ctx, filter)
		relay.Close()
		if err != nil || len(events) == 0 {
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
	privHex := string(nostrPrivKey)
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
