package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"go.etcd.io/bbolt"
)

// IdentityRecord represents a globally discoverable identity anchored to a registry.
type IdentityRecord struct {
	Handle    string    `json:"handle,omitempty"`    // e.g., "@alice"
	KEMPubKey []byte    `json:"kem_pub"`             // ML-KEM-768+X25519
	SIGPubKey []byte    `json:"sig_pub"`             // ML-DSA-87
	Timestamp time.Time `json:"timestamp"`           // Time of anchoring
	Signature []byte    `json:"signature,omitempty"` // Self-signature of the record to prove ownership
	Revoked   bool      `json:"revoked,omitempty"`   // Revocation status
}

// Sign self-signs the record using an ML-DSA private key.
func (r *IdentityRecord) Sign(privKey []byte) error {
	// Reset signature before signing
	r.Signature = nil
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

// Verify checks the record's self-signature against its public signing key.
func (r *IdentityRecord) Verify() bool {
	if len(r.Signature) == 0 {
		return false
	}
	sig := r.Signature
	r.Signature = nil
	defer func() { r.Signature = sig }()

	data, _ := json.Marshal(r)
	return VerifySignature(data, sig, r.SIGPubKey)
}

// GetDNSRecordString returns the string a user needs to add to their DNS.
func GetDNSRecordString(record *IdentityRecord) (string, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("v=maknoon1;data=%s", encoded), nil
}

// GetCompactDNSRecordString returns a compressed smaller version of the record (no handle/sig).
func GetCompactDNSRecordString(record *IdentityRecord) (string, error) {
	clone := *record
	clone.Handle = ""
	clone.Signature = nil
	data, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}

	// Compress using Zstd
	var b bytes.Buffer
	enc, _ := zstd.NewWriter(&b, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	enc.Write(data)
	enc.Close()

	encoded := base64.StdEncoding.EncodeToString(b.Bytes())
	return fmt.Sprintf("v=maknoon1;z=1;data=%s", encoded), nil
}

// parseMaknoonTXT parses a Maknoon record from a TXT string.
func parseMaknoonTXT(txt string) (*IdentityRecord, error) {
	if !strings.HasPrefix(txt, "v=maknoon1;") {
		return nil, errors.New("invalid record format")
	}

	isCompressed := strings.Contains(txt, ";z=1;")
	dataPart := ""
	if idx := strings.Index(txt, "data="); idx != -1 {
		dataPart = txt[idx+5:]
	} else {
		return nil, errors.New("missing data in record")
	}

	raw, err := base64.StdEncoding.DecodeString(dataPart)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	if isCompressed {
		dec, _ := zstd.NewReader(bytes.NewReader(raw))
		decompressed, err := io.ReadAll(dec)
		if err != nil {
			return nil, fmt.Errorf("zstd decompress failed: %w", err)
		}
		raw = decompressed
	}

	var record IdentityRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("json unmarshal failed: %w", err)
	}

	// For full records, verify signature.
	if len(record.Signature) > 0 {
		if !record.Verify() {
			return nil, errors.New("record signature verification failed")
		}
	}

	return &record, nil
}

// IdentityRegistry defines the bridge between Maknoon and a decentralized ledger (dPKI).
type IdentityRegistry interface {
	// Resolve fetches an identity record by its handle.
	Resolve(ctx context.Context, handle string) (*IdentityRecord, error)

	// Publish anchors a new identity or updates an existing one.
	Publish(ctx context.Context, record *IdentityRecord) error

	// PublishWithKey anchors a new identity using a specific discovery key (e.g. Ed25519 for DHT).
	PublishWithKey(ctx context.Context, record *IdentityRecord, discPrivKey []byte) error

	// Revoke marks an identity as compromised or inactive.
	Revoke(ctx context.Context, handle string, proof []byte) error
}

// MockRegistry is a memory-based implementation for development and CI.
type MockRegistry struct {
	records map[string]*IdentityRecord
	mu      sync.RWMutex
}

func NewMockRegistry() *MockRegistry {
	return &MockRegistry{records: make(map[string]*IdentityRecord)}
}

func (r *MockRegistry) Resolve(_ context.Context, handle string) (*IdentityRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.records[strings.ToLower(handle)]
	if !ok {
		return nil, fmt.Errorf("handle '%s' not found", handle)
	}
	return record, nil
}

func (r *MockRegistry) Publish(_ context.Context, record *IdentityRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[strings.ToLower(record.Handle)] = record
	return nil
}

func (r *MockRegistry) PublishWithKey(ctx context.Context, record *IdentityRecord, _ []byte) error {
	return r.Publish(ctx, record)
}

func (r *MockRegistry) Revoke(_ context.Context, handle string, _ []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.records, strings.ToLower(handle))
	return nil
}

// BoltRegistry is a persistent, bbolt-based implementation simulating a blockchain ledger.
type BoltRegistry struct {
	db   *bbolt.DB
	path string
}

const registryBucket = "identities"

func NewBoltRegistry() (*BoltRegistry, error) {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, MaknoonDir, "registry.db")

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open registry database: %w", err)
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(registryBucket))
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	return &BoltRegistry{db: db, path: path}, nil
}

func (r *BoltRegistry) Close() error {
	return r.db.Close()
}

func (r *BoltRegistry) Resolve(_ context.Context, handle string) (*IdentityRecord, error) {
	var record IdentityRecord
	err := r.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(registryBucket))
		v := b.Get([]byte(strings.ToLower(handle)))
		if v == nil {
			return fmt.Errorf("handle '%s' not found", handle)
		}
		return json.Unmarshal(v, &record)
	})
	if err != nil {
		return nil, err
	}
	if record.Revoked {
		return nil, errors.New("identity has been revoked")
	}

	// For Bolt registry, records should have signatures.
	if len(record.Signature) > 0 && !record.Verify() {
		return nil, errors.New("identity record signature verification failed")
	}

	return &record, nil
}

func (r *BoltRegistry) Publish(_ context.Context, record *IdentityRecord) error {
	if len(record.Signature) > 0 && !record.Verify() {
		return errors.New("cannot publish unverified record")
	}

	return r.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(registryBucket))
		data, _ := json.Marshal(record)
		return b.Put([]byte(strings.ToLower(record.Handle)), data)
	})
}

func (r *BoltRegistry) PublishWithKey(ctx context.Context, record *IdentityRecord, _ []byte) error {
	return r.Publish(ctx, record)
}

func (r *BoltRegistry) Revoke(_ context.Context, handle string, proof []byte) error {
	return r.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(registryBucket))
		v := b.Get([]byte(strings.ToLower(handle)))
		if v == nil {
			return fmt.Errorf("handle '%s' not found", handle)
		}
		var record IdentityRecord
		if err := json.Unmarshal(v, &record); err != nil {
			return err
		}

		// In a real scenario, 'proof' would be a signed revocation message.
		// For POC, we verify the proof against the existing SIG key.
		lowerHandle := strings.ToLower(handle)
		if !VerifySignature([]byte("REVOKE:"+lowerHandle), proof, record.SIGPubKey) {
			return errors.New("invalid revocation proof")
		}

		record.Revoked = true
		data, _ := json.Marshal(record)
		return b.Put([]byte(strings.ToLower(handle)), data)
	})
}

// GlobalRegistry is the active dPKI provider.
var GlobalRegistry IdentityRegistry

func init() {
	// 1. Attempt to initialize the Bolt registry.
	reg, err := NewBoltRegistry()
	if err == nil {
		GlobalRegistry = reg
		return
	}

	// 2. Fallback to MockRegistry (memory-only) for CI/Restricted environments.
	GlobalRegistry = NewMockRegistry()
}
