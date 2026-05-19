package crypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

// resolveCacheTTL is how long a successful identity resolution is cached.
// Keeps agents fast across repeated calls while still picking up republished
// records within a reasonable window.
const resolveCacheTTL = 5 * time.Minute

type cachedRecord struct {
	record    *IdentityRecord
	expiresAt time.Time
}

// IdentityRegistry defines the interface for publishing and discovering public keys.
type IdentityRegistry interface {
	Resolve(ctx context.Context, handle string) (*IdentityRecord, error)
	Publish(ctx context.Context, record *IdentityRecord) error
	Revoke(ctx context.Context, handle string, proof []byte) error
}

// IdentityRecord is the self-signed payload stored in registries.
type IdentityRecord struct {
	Handle     string    `json:"handle"`
	KEMPubKey  []byte    `json:"kem_pub"`
	SIGPubKey  []byte    `json:"sig_pub"`
	Multiaddrs []string  `json:"multiaddrs,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"` // zero = no expiry (backwards-compatible)
	Signature  []byte    `json:"signature,omitempty"`
	Revoked    bool      `json:"revoked,omitempty"`
}

// IsExpired returns true if the record has a non-zero ExpiresAt that is in the past.
// Records with zero ExpiresAt are treated as never expiring (legacy compatibility).
func (r *IdentityRecord) IsExpired() bool {
	return !r.ExpiresAt.IsZero() && time.Now().After(r.ExpiresAt)
}

// Sign signs the record using the user's ML-DSA private key.
func (r *IdentityRecord) Sign(privKey []byte) error {
	r.Signature = nil // Ensure sig is empty before signing
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}

	sig, err := SignData(data, privKey)
	if err != nil {
		return err
	}
	r.Signature = sig
	return nil
}

// Verify checks the ML-DSA signature on the record.
func (r *IdentityRecord) Verify() bool {
	if len(r.Signature) == 0 {
		return false
	}

	sig := r.Signature
	r.Signature = nil
	data, _ := json.Marshal(r)
	r.Signature = sig

	return VerifySignature(data, sig, r.SIGPubKey)
}

// --- Record Serialization Helpers ---

// GetDNSRecordString returns a compressed TXT record value.
func GetDNSRecordString(record *IdentityRecord) (string, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	return "v=maknoon1;data=" + base64.StdEncoding.EncodeToString(data), nil
}

// GetCompactDNSRecordString returns a version with Zstd compression.
func GetCompactDNSRecordString(record *IdentityRecord) (string, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return "", err
	}

	encoder, _ := zstd.NewWriter(nil)
	compressed := encoder.EncodeAll(data, make([]byte, 0, len(data)))

	return "v=maknoon1;z=1;data=" + base64.StdEncoding.EncodeToString(compressed), nil
}

func parseMaknoonTXT(txt string) (*IdentityRecord, error) {
	if !strings.HasPrefix(txt, "v=maknoon1;") {
		return nil, errors.New("invalid record format")
	}

	isCompressed := strings.Contains(txt, ";z=1;")
	dataPart := ""
	if idx := strings.Index(txt, "data="); idx != -1 {
		dataPart = txt[idx+5:]
	} else {
		return nil, errors.New("missing data field")
	}

	decoded, err := base64.StdEncoding.DecodeString(dataPart)
	if err != nil {
		return nil, err
	}

	if isCompressed {
		decoder, _ := zstd.NewReader(nil)
		decoded, err = decoder.DecodeAll(decoded, nil)
		if err != nil {
			return nil, fmt.Errorf("decompression failed: %w", err)
		}
	}

	var record IdentityRecord
	if err := json.Unmarshal(decoded, &record); err != nil {
		return nil, fmt.Errorf("json unmarshal failed: %w", err)
	}

	if !record.Verify() {
		return nil, errors.New("identity record signature verification failed")
	}

	return &record, nil
}

// MultiRegistry combines multiple registries for discovery. Successful
// resolutions are cached for resolveCacheTTL so that repeated lookups within
// a single agent session avoid redundant relay round-trips.
type MultiRegistry struct {
	Registries []IdentityRegistry

	mu    sync.Mutex
	cache map[string]cachedRecord // keyed by handle
}

var registryFactories = make(map[string]func(conf *Config) IdentityRegistry)

// RegisterRegistry adds a new registry factory to the global map.
func RegisterRegistry(name string, factory func(conf *Config) IdentityRegistry) {
	registryFactories[name] = factory
}

// NewIdentityRegistry returns a multi-registry based on configuration.
// If conf is nil, the global configuration is used.
func NewIdentityRegistry(conf *Config) IdentityRegistry {
	if conf == nil {
		conf = GetGlobalConfig()
	}
	active := conf.IdentityRegistries
	if len(active) == 0 {
		// Nostr is the primary registry (concurrent relay fan-out).
		// DNS is a real fallback via _maknoon.<domain> TXT records + deSEC API publishing.
		// BEP-44 DHT is available as an explicit opt-in (add "bep44" to Config.IdentityRegistries)
		// but resolution is disabled since full-record fetch requires P2P transport.
		active = []string{"nostr", "dns"}
	}

	mr := &MultiRegistry{}
	for _, name := range active {
		if factory, ok := registryFactories[name]; ok {
			mr.Registries = append(mr.Registries, factory(conf))
		}
	}
	return mr
}

func (r *MultiRegistry) Resolve(ctx context.Context, handle string) (*IdentityRecord, error) {
	// Check the in-process cache first. This avoids relay round-trips on every
	// call from an agent session while still honoring the record's own ExpiresAt.
	r.mu.Lock()
	if r.cache == nil {
		r.cache = make(map[string]cachedRecord)
	}
	if cached, ok := r.cache[handle]; ok && time.Now().Before(cached.expiresAt) {
		r.mu.Unlock()
		return cached.record, nil
	}
	r.mu.Unlock()

	for _, reg := range r.Registries {
		record, err := reg.Resolve(ctx, handle)
		if err != nil {
			continue
		}
		if record.IsExpired() {
			continue // record is stale; try next registry for a fresher one
		}
		// Cache the fresh record for the next resolveCacheTTL window.
		r.mu.Lock()
		r.cache[handle] = cachedRecord{record: record, expiresAt: time.Now().Add(resolveCacheTTL)}
		r.mu.Unlock()
		return record, nil
	}
	return nil, fmt.Errorf("could not resolve identity for %s", handle)
}

func (r *MultiRegistry) Publish(ctx context.Context, record *IdentityRecord) error {
	for _, reg := range r.Registries {
		if err := reg.Publish(ctx, record); err == nil {
			return nil
		}
	}
	return fmt.Errorf("failed to publish identity to any registry")
}

func (r *MultiRegistry) Revoke(ctx context.Context, handle string, proof []byte) error {
	for _, reg := range r.Registries {
		if err := reg.Revoke(ctx, handle, proof); err == nil {
			return nil
		}
	}
	return fmt.Errorf("failed to revoke identity from any registry")
}
