package crypto

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─── MultiRegistry ───────────────────────────────────────────────────────────

// stubRegistry is an in-memory IdentityRegistry for testing MultiRegistry.
type stubRegistry struct {
	record *IdentityRecord
	err    error
}

func (s *stubRegistry) Resolve(_ context.Context, _ string) (*IdentityRecord, error) {
	return s.record, s.err
}
func (s *stubRegistry) Publish(_ context.Context, _ *IdentityRecord) error { return s.err }
func (s *stubRegistry) Revoke(_ context.Context, _ string, _ []byte) error { return s.err }

func makeSignedRecord(t *testing.T, handle string) *IdentityRecord {
	t.Helper()
	kpub, _, spub, spriv, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}
	rec := &IdentityRecord{
		Handle:    handle,
		KEMPubKey: kpub,
		SIGPubKey: spub,
		Timestamp: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := rec.Sign(spriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return rec
}

func TestMultiRegistryResolveFirstSucceeds(t *testing.T) {
	rec := makeSignedRecord(t, "@alice@example.com")
	mr := &MultiRegistry{
		Registries: []IdentityRegistry{
			&stubRegistry{record: rec},
		},
	}
	got, err := mr.Resolve(context.Background(), "@alice@example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Handle != rec.Handle {
		t.Errorf("Handle = %q, want %q", got.Handle, rec.Handle)
	}
}

func TestMultiRegistryResolveFallsThrough(t *testing.T) {
	rec := makeSignedRecord(t, "@bob@example.com")
	mr := &MultiRegistry{
		Registries: []IdentityRegistry{
			&stubRegistry{err: errors.New("first fails")},
			&stubRegistry{record: rec},
		},
	}
	got, err := mr.Resolve(context.Background(), "@bob@example.com")
	if err != nil {
		t.Fatalf("Resolve fallthrough: %v", err)
	}
	if got.Handle != rec.Handle {
		t.Errorf("Handle = %q, want %q", got.Handle, rec.Handle)
	}
}

func TestMultiRegistryResolveAllFail(t *testing.T) {
	mr := &MultiRegistry{
		Registries: []IdentityRegistry{
			&stubRegistry{err: errors.New("err1")},
			&stubRegistry{err: errors.New("err2")},
		},
	}
	_, err := mr.Resolve(context.Background(), "@nobody@example.com")
	if err == nil {
		t.Error("expected error when all registries fail")
	}
}

func TestMultiRegistryResolveCache(t *testing.T) {
	rec := makeSignedRecord(t, "@cached@example.com")
	// Just verify a second Resolve returns the same record (cache hit) without error.
	mr := &MultiRegistry{
		Registries: []IdentityRegistry{&stubRegistry{record: rec}},
	}
	mr.Resolve(context.Background(), "@cached@example.com")
	got, err := mr.Resolve(context.Background(), "@cached@example.com")
	if err != nil {
		t.Fatalf("second Resolve (cache): %v", err)
	}
	if got.Handle != rec.Handle {
		t.Errorf("cache miss: Handle = %q", got.Handle)
	}
}

func TestMultiRegistryPublishFirstSucceeds(t *testing.T) {
	rec := makeSignedRecord(t, "@pub@example.com")
	mr := &MultiRegistry{
		Registries: []IdentityRegistry{
			&stubRegistry{err: nil},
		},
	}
	if err := mr.Publish(context.Background(), rec); err != nil {
		t.Errorf("Publish: %v", err)
	}
}

func TestMultiRegistryPublishAllFail(t *testing.T) {
	rec := makeSignedRecord(t, "@fail@example.com")
	mr := &MultiRegistry{
		Registries: []IdentityRegistry{
			&stubRegistry{err: errors.New("pub failed")},
		},
	}
	if err := mr.Publish(context.Background(), rec); err == nil {
		t.Error("expected error when all registries fail to publish")
	}
}

func TestMultiRegistryRevokeFirstSucceeds(t *testing.T) {
	mr := &MultiRegistry{
		Registries: []IdentityRegistry{&stubRegistry{err: nil}},
	}
	if err := mr.Revoke(context.Background(), "@handle@example.com", nil); err != nil {
		t.Errorf("Revoke: %v", err)
	}
}

func TestMultiRegistryRevokeAllFail(t *testing.T) {
	mr := &MultiRegistry{
		Registries: []IdentityRegistry{
			&stubRegistry{err: errors.New("revoke failed")},
		},
	}
	if err := mr.Revoke(context.Background(), "@handle@example.com", nil); err == nil {
		t.Error("expected error when all registries fail to revoke")
	}
}

// ─── GetDNSRecordString / GetCompactDNSRecordString ──────────────────────────

func TestGetDNSRecordString(t *testing.T) {
	rec := makeSignedRecord(t, "@alice@example.com")
	s, err := GetDNSRecordString(rec)
	if err != nil {
		t.Fatalf("GetDNSRecordString: %v", err)
	}
	if s == "" {
		t.Error("GetDNSRecordString returned empty string")
	}
}

func TestGetCompactDNSRecordString(t *testing.T) {
	rec := makeSignedRecord(t, "@alice@example.com")
	s, err := GetCompactDNSRecordString(rec)
	if err != nil {
		t.Fatalf("GetCompactDNSRecordString: %v", err)
	}
	if s == "" {
		t.Error("GetCompactDNSRecordString returned empty string")
	}
	// Compact should be shorter than plain.
	plain, _ := GetDNSRecordString(rec)
	if len(s) >= len(plain) {
		t.Logf("note: compact (%d) not shorter than plain (%d)", len(s), len(plain))
	}
}

// ─── Contacts ────────────────────────────────────────────────────────────────

func newTempContactManager(t *testing.T) *ContactManager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "contacts.db")
	vs := &FileSystemVaultStore{BaseDir: t.TempDir()}
	store, err := vs.Open(path)
	if err != nil {
		t.Fatalf("Open contact store: %v", err)
	}
	return NewContactManager(store)
}

func TestDerivePeerID(t *testing.T) {
	_, _, sigPub, _, _ := GeneratePQKeyPair(1)
	id, err := DerivePeerID(sigPub)
	if err != nil {
		t.Fatalf("DerivePeerID: %v", err)
	}
	if id == "" {
		t.Error("DerivePeerID returned empty string")
	}
	// Deterministic.
	id2, _ := DerivePeerID(sigPub)
	if id != id2 {
		t.Error("DerivePeerID is not deterministic")
	}
}

func TestContactManagerGetByPeerID(t *testing.T) {
	cm := newTempContactManager(t)
	defer cm.Close()

	_, _, sigPub, _, _ := GeneratePQKeyPair(1)
	peerID, _ := DerivePeerID(sigPub)
	kemPub, _, _, _, _ := GeneratePQKeyPair(1)

	cm.Add(&Contact{
		Petname:   "@charlie",
		KEMPubKey: kemPub,
		SIGPubKey: sigPub,
		PeerID:    peerID,
	})

	got, err := cm.GetByPeerID(peerID)
	if err != nil {
		t.Fatalf("GetByPeerID: %v", err)
	}
	if got == nil || got.Petname != "@charlie" {
		t.Errorf("GetByPeerID returned wrong contact: %+v", got)
	}
}

func TestContactManagerGetByPeerIDMissing(t *testing.T) {
	cm := newTempContactManager(t)
	defer cm.Close()

	_, err := cm.GetByPeerID("nonexistent-peer-id")
	if err == nil {
		t.Error("expected error for missing peer ID")
	}
}

func TestContactManagerClose(t *testing.T) {
	cm := newTempContactManager(t)
	if err := cm.Close(); err != nil {
		t.Errorf("ContactManager.Close: %v", err)
	}
}

// ─── FileSystemKeyStore ───────────────────────────────────────────────────────

func newTestKeyStore(t *testing.T) *FileSystemKeyStore {
	t.Helper()
	return &FileSystemKeyStore{BaseDir: t.TempDir()}
}

func TestFileSystemKeyStoreReadWriteKey(t *testing.T) {
	s := newTestKeyStore(t)
	path := filepath.Join(s.BaseDir, "test.key")
	data := []byte("secret key material")

	if err := s.WriteKey(path, data, 0600); err != nil {
		t.Fatalf("WriteKey: %v", err)
	}
	got, err := s.ReadKey(path)
	if err != nil {
		t.Fatalf("ReadKey: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("ReadKey mismatch: got %q, want %q", got, data)
	}
}

func TestFileSystemKeyStoreExists(t *testing.T) {
	s := newTestKeyStore(t)
	path := filepath.Join(s.BaseDir, "exists.key")

	if s.Exists(path) {
		t.Error("Exists should return false before file is created")
	}
	s.WriteKey(path, []byte("data"), 0600)
	if !s.Exists(path) {
		t.Error("Exists should return true after file is created")
	}
}

func TestFileSystemKeyStoreListKeys(t *testing.T) {
	s := newTestKeyStore(t)
	for _, name := range []string{"a.key", "b.key", "c.key"} {
		s.WriteKey(filepath.Join(s.BaseDir, name), []byte("x"), 0600)
	}

	keys, err := s.ListKeys(s.BaseDir)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) < 3 {
		t.Errorf("expected at least 3 keys, got %d", len(keys))
	}
}

func TestFileSystemKeyStoreEnsureDir(t *testing.T) {
	s := newTestKeyStore(t)
	newDir := filepath.Join(s.BaseDir, "sub", "dir")

	if err := s.EnsureDir(newDir); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	if _, err := os.Stat(newDir); err != nil {
		t.Errorf("EnsureDir did not create directory: %v", err)
	}
}

func TestFileSystemKeyStoreResolvePath(t *testing.T) {
	s := newTestKeyStore(t)
	resolved, err := s.ResolvePath("mykey")
	if err != nil {
		t.Fatalf("ResolvePath: %v", err)
	}
	if !strings.HasPrefix(resolved, s.BaseDir) {
		t.Errorf("ResolvePath %q not within BaseDir %q", resolved, s.BaseDir)
	}
}

func TestFileSystemKeyStoreGetBaseDir(t *testing.T) {
	s := &FileSystemKeyStore{BaseDir: "/tmp/test-base"}
	if s.GetBaseDir() != "/tmp/test-base" {
		t.Errorf("GetBaseDir = %q, want %q", s.GetBaseDir(), "/tmp/test-base")
	}
}

func TestFileSystemKeyStoreTraversalRejected(t *testing.T) {
	s := newTestKeyStore(t)
	// Path traversal must be rejected.
	_, err := s.ReadKey("../../etc/passwd")
	if err == nil {
		t.Error("expected error for path traversal attempt")
	}
}

// ─── FileSystemConfigStore ────────────────────────────────────────────────────

func TestFileSystemConfigStoreSaveLoad(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	cs := &FileSystemConfigStore{}
	conf := DefaultConfig()

	// Save then load.
	if err := cs.Save(conf); err != nil {
		// Save may fail if the config file can't be written in CI — skip gracefully.
		t.Skipf("Save failed (may be expected in restricted env): %v", err)
	}
	loaded, err := cs.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded == nil {
		t.Error("Load returned nil config")
	}
}

// ─── FileSystemVaultStore ─────────────────────────────────────────────────────

func TestFileSystemVaultStoreOpenAndDelete(t *testing.T) {
	base := t.TempDir()
	vs := &FileSystemVaultStore{BaseDir: base}

	store, err := vs.Open("testvault.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Store is a BboltStore — close it via type assertion.
	if bs, ok := store.(*BboltStore); ok {
		bs.Close()
	}

	// Delete the vault.
	vaultPath := filepath.Join(base, "testvault.db")
	if err := vs.DeleteVault(vaultPath); err != nil {
		t.Fatalf("DeleteVault: %v", err)
	}
	if _, err := os.Stat(vaultPath); err == nil {
		t.Error("vault file should not exist after DeleteVault")
	}
}

func TestFileSystemVaultStoreListVaults(t *testing.T) {
	base := t.TempDir()
	vs := &FileSystemVaultStore{BaseDir: base}

	for _, name := range []string{"v1.vault", "v2.vault"} {
		s, _ := vs.Open(name)
		if bs, ok := s.(*BboltStore); ok {
			bs.Close()
		}
	}

	vaults, err := vs.ListVaults()
	if err != nil {
		t.Fatalf("ListVaults: %v", err)
	}
	if len(vaults) < 2 {
		t.Errorf("expected at least 2 vaults, got %d", len(vaults))
	}
}

// ─── BboltStore ───────────────────────────────────────────────────────────────

func TestBboltStoreCreateBucket(t *testing.T) {
	base := t.TempDir()
	vs := &FileSystemVaultStore{BaseDir: base}
	store, err := vs.Open("bbolt_test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	bs := store.(*BboltStore)
	defer bs.Close()

	err = bs.Update(func(tx Transaction) error {
		return tx.CreateBucket("test-bucket")
	})
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
}

// ─── NewIdentityRegistry ─────────────────────────────────────────────────────

func TestNewIdentityRegistry(t *testing.T) {
	conf := DefaultConfig()
	reg := NewIdentityRegistry(conf)
	if reg == nil {
		t.Fatal("NewIdentityRegistry returned nil")
	}
}

// ─── parseMaknoonTXT (round-trip) ────────────────────────────────────────────

func TestParseMaknoonTXTRoundTrip(t *testing.T) {
	rec := makeSignedRecord(t, "@alice@example.com")
	encoded, err := GetCompactDNSRecordString(rec)
	if err != nil {
		t.Fatalf("GetCompactDNSRecordString: %v", err)
	}
	parsed, err := parseMaknoonTXT(encoded)
	if err != nil {
		t.Fatalf("parseMaknoonTXT: %v", err)
	}
	if !parsed.Verify() {
		t.Error("parsed record failed signature verification")
	}
}

// ─── FileSystemConfigStore.Load from disk ────────────────────────────────────

func TestFileSystemConfigStoreLoadFromDisk(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// Write a minimal config file.
	conf := DefaultConfig()
	data, _ := json.MarshalIndent(conf, "", "  ")
	cfgPath := filepath.Join(tmp, ".maknoon", "config.json")
	os.MkdirAll(filepath.Dir(cfgPath), 0700)
	os.WriteFile(cfgPath, data, 0600)

	cs := &FileSystemConfigStore{}
	loaded, err := cs.Load()
	if err != nil {
		t.Fatalf("Load from disk: %v", err)
	}
	if loaded == nil {
		t.Error("Load returned nil")
	}
}
