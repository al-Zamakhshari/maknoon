package crypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

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
	Signature  []byte    `json:"signature,omitempty"`
	Revoked    bool      `json:"revoked,omitempty"`
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

// MultiRegistry combines multiple registries for discovery.
type MultiRegistry struct {
	Registries []IdentityRegistry
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
		active = []string{"dns", "nostr"} // Default fallback
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
	for _, reg := range r.Registries {
		if record, err := reg.Resolve(ctx, handle); err == nil {
			return record, nil
		}
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
