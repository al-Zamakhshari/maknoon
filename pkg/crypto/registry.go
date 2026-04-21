package crypto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// IdentityRecord represents a globally discoverable identity anchored to a registry.
type IdentityRecord struct {
	Handle    string    `json:"handle"`    // e.g., "@alice"
	KEMPubKey []byte    `json:"kem_pub"`   // ML-KEM-768+X25519
	SIGPubKey []byte    `json:"sig_pub"`   // ML-DSA-87
	Timestamp time.Time `json:"timestamp"` // Time of anchoring
	Signature []byte    `json:"signature"` // Self-signature of the record to prove ownership
	Revoked   bool      `json:"revoked"`   // Revocation status
}

// IdentityRegistry defines the bridge between Maknoon and a decentralized ledger (dPKI).
type IdentityRegistry interface {
	// Resolve fetches an identity record by its handle.
	Resolve(ctx context.Context, handle string) (*IdentityRecord, error)

	// Publish anchors a new identity or updates an existing one.
	// requires proof of ownership (self-signature).
	Publish(ctx context.Context, record *IdentityRecord) error

	// Revoke marks an identity as compromised or inactive.
	Revoke(ctx context.Context, handle string, proof []byte) error
}

// MockRegistry is a persistent, file-based implementation for development and testing.
type MockRegistry struct {
	mu      sync.RWMutex
	records map[string]*IdentityRecord
	path    string
}

func NewMockRegistry() *MockRegistry {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, MaknoonDir, "registry.json")
	m := &MockRegistry{
		records: make(map[string]*IdentityRecord),
		path:    path,
	}
	m.load()
	return m
}

func (m *MockRegistry) load() {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := os.ReadFile(m.path)
	if err == nil {
		_ = json.Unmarshal(data, &m.records)
	}
}

func (m *MockRegistry) save() {
	data, _ := json.MarshalIndent(m.records, "", "  ")
	_ = os.WriteFile(m.path, data, 0600)
}

func (m *MockRegistry) Resolve(_ context.Context, handle string) (*IdentityRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	record, ok := m.records[handle]
	if !ok {
		return nil, fmt.Errorf("handle '%s' not found in registry", handle)
	}
	if record.Revoked {
		return nil, errors.New("identity has been revoked")
	}
	return record, nil
}

func (m *MockRegistry) Publish(_ context.Context, record *IdentityRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[record.Handle] = record
	m.save()
	return nil
}

func (m *MockRegistry) Revoke(_ context.Context, handle string, _ []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if record, ok := m.records[handle]; ok {
		record.Revoked = true
		m.save()
		return nil
	}
	return fmt.Errorf("handle '%s' not found", handle)
}

// GlobalRegistry is the active dPKI provider. 
// Defaulting to nil/Mock allows for incremental adoption.
var GlobalRegistry IdentityRegistry = NewMockRegistry()
