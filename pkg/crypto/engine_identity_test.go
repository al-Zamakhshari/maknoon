package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

// engineForIdentity returns a fully initialised engine wired to a temp HOME.
func engineForIdentity(t *testing.T) *Engine {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	conf := DefaultConfig()
	e, err := NewEngine(&HumanPolicy{}, nil, conf, nil, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// --- CreateIdentity ---

func TestEngineCreateIdentity(t *testing.T) {
	e := engineForIdentity(t)
	res, err := e.CreateIdentity(nil, "alice", []byte("passphrase"), "", false, "")
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	if res == nil {
		t.Fatal("CreateIdentity returned nil result")
	}
}

func TestEngineCreateIdentityTwiceOverwrites(t *testing.T) {
	// CreateIdentity overwrites silently — second call must also succeed.
	e := engineForIdentity(t)
	if _, err := e.CreateIdentity(nil, "bob", []byte("pass1"), "", false, ""); err != nil {
		t.Fatalf("first CreateIdentity: %v", err)
	}
	if _, err := e.CreateIdentity(nil, "bob", []byte("pass2"), "", false, ""); err != nil {
		t.Fatalf("second CreateIdentity (overwrite): %v", err)
	}
	// The key is now locked with pass2.
	id, err := e.LoadIdentity(nil, "bob", []byte("pass2"), "", false)
	if err != nil {
		t.Fatalf("LoadIdentity with new pass: %v", err)
	}
	id.Wipe()
}

// --- IdentityActive ---

func TestEngineIdentityActive(t *testing.T) {
	e := engineForIdentity(t)
	e.CreateIdentity(nil, "eve", []byte("pass"), "", false, "")

	ids, err := e.IdentityActive(nil)
	if err != nil {
		t.Fatalf("IdentityActive: %v", err)
	}
	found := false
	for _, id := range ids {
		if id == "eve" {
			found = true
		}
	}
	if !found {
		t.Errorf("'eve' not in IdentityActive list: %v", ids)
	}
}

// --- IdentityInfo ---

func TestEngineIdentityInfo(t *testing.T) {
	e := engineForIdentity(t)
	e.CreateIdentity(nil, "carol", []byte("pass"), "", false, "")

	info, err := e.IdentityInfo(nil, "carol")
	if err != nil {
		t.Fatalf("IdentityInfo: %v", err)
	}
	if info == nil {
		t.Fatal("IdentityInfo returned nil")
	}
}

func TestEngineIdentityInfoMissingReturnsEmpty(t *testing.T) {
	// GetIdentityInfo never errors for missing identities — it returns empty fields.
	e := engineForIdentity(t)
	info, err := e.IdentityInfo(nil, "nobody")
	if err != nil {
		t.Fatalf("IdentityInfo for missing identity: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil result even for missing identity")
	}
	// KEMPub is empty for an identity that was never created.
	if info.KEMPub != "" {
		t.Errorf("expected empty KEMPub for missing identity, got %q", info.KEMPub)
	}
}

// --- IdentityDelete ---

func TestEngineIdentityDelete(t *testing.T) {
	e := engineForIdentity(t)
	e.CreateIdentity(nil, "del-me", []byte("pass"), "", false, "")

	// Verify the key exists before deletion.
	before, _ := e.IdentityInfo(nil, "del-me")
	if before.KEMPub == "" {
		t.Fatal("identity should have KEMPub before deletion")
	}

	if err := e.IdentityDelete(nil, "del-me"); err != nil {
		t.Fatalf("IdentityDelete: %v", err)
	}

	// After deletion, key files are gone — IdentityInfo returns empty KEMPub.
	after, _ := e.IdentityInfo(nil, "del-me")
	if after.KEMPub != "" {
		t.Error("KEMPub should be empty after deletion")
	}
}

// --- IdentityRename ---

func TestEngineIdentityRename(t *testing.T) {
	e := engineForIdentity(t)
	e.CreateIdentity(nil, "old-name", []byte("pass"), "", false, "")

	if err := e.IdentityRename(nil, "old-name", "new-name"); err != nil {
		t.Fatalf("IdentityRename: %v", err)
	}
	_, err := e.IdentityInfo(nil, "new-name")
	if err != nil {
		t.Errorf("renamed identity should be accessible: %v", err)
	}
}

// --- LoadIdentity ---

func TestEngineLoadIdentity(t *testing.T) {
	e := engineForIdentity(t)
	e.CreateIdentity(nil, "loadme", []byte("loadpass"), "", false, "")

	id, err := e.LoadIdentity(nil, "loadme", []byte("loadpass"), "", false)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if id == nil {
		t.Fatal("LoadIdentity returned nil")
	}
	id.Wipe()
}

func TestEngineLoadIdentityWrongPass(t *testing.T) {
	e := engineForIdentity(t)
	e.CreateIdentity(nil, "locked", []byte("correct"), "", false, "")

	_, err := e.LoadIdentity(nil, "locked", []byte("wrong"), "", false)
	if err == nil {
		t.Error("expected error for wrong passphrase")
	}
}

// --- LoadPrivateKey ---

func TestEngineLoadPrivateKey(t *testing.T) {
	e := engineForIdentity(t)
	e.CreateIdentity(nil, "keytest", []byte("kpass"), "", false, "")

	// Resolve the base key path, then load the .kem.key file.
	basePath, _, err := e.ResolveBaseKeyPath(nil, "keytest")
	if err != nil {
		t.Fatalf("ResolveBaseKeyPath: %v", err)
	}
	kemKeyPath := basePath + ".kem.key"

	key, err := e.LoadPrivateKey(nil, kemKeyPath, []byte("kpass"), "", false)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if len(key) == 0 {
		t.Error("LoadPrivateKey returned empty key")
	}
	SafeClear(key)
}

// --- ResolveKeyPath ---

func TestEngineResolveKeyPath(t *testing.T) {
	e := engineForIdentity(t)
	e.CreateIdentity(nil, "resolveme", []byte("pass"), "", false, "")

	basePath, _, err := e.ResolveBaseKeyPath(nil, "resolveme")
	if err != nil {
		t.Fatalf("ResolveBaseKeyPath: %v", err)
	}
	if basePath == "" {
		t.Error("ResolveBaseKeyPath returned empty path")
	}

	// ResolveKeyPath returns the path if the file exists on disk.
	kemPubPath := basePath + ".kem.pub"
	resolved := e.ResolveKeyPath(nil, kemPubPath, "")
	if resolved == "" {
		t.Errorf("ResolveKeyPath returned empty for existing pub key: %s", kemPubPath)
	}
}

// --- ContactAdd / ContactList / ContactDelete via engine ---

func TestEngineContactAddListDelete(t *testing.T) {
	e := engineForIdentity(t)

	// Generate a key pair to use as a contact.
	kemPub, _, sigPub, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}

	kemHex := encodeHex(kemPub)
	sigHex := encodeHex(sigPub)

	if err := e.ContactAdd(nil, "@bob", kemHex, sigHex, "test note"); err != nil {
		t.Fatalf("ContactAdd: %v", err)
	}

	contacts, err := e.ContactList(nil)
	if err != nil {
		t.Fatalf("ContactList: %v", err)
	}
	found := false
	for _, c := range contacts {
		if c.Petname == "@bob" {
			found = true
		}
	}
	if !found {
		t.Error("@bob not found after ContactAdd")
	}

	if err := e.ContactDelete(nil, "@bob"); err != nil {
		t.Fatalf("ContactDelete: %v", err)
	}
	contacts, _ = e.ContactList(nil)
	for _, c := range contacts {
		if c.Petname == "@bob" {
			t.Error("@bob still present after ContactDelete")
		}
	}
}

// --- IdentitySplit / IdentityCombine ---

func TestEngineIdentitySplitAndCombine(t *testing.T) {
	e := engineForIdentity(t)
	e.CreateIdentity(nil, "split-id", []byte("spass"), "", false, "")

	shards, err := e.IdentitySplit(nil, "split-id", 2, 3, "spass")
	if err != nil {
		t.Fatalf("IdentitySplit: %v", err)
	}
	if len(shards) != 3 {
		t.Fatalf("expected 3 shards, got %d", len(shards))
	}

	outPath := filepath.Join(t.TempDir(), "recovered-id")
	recoveredPath, err := e.IdentityCombine(nil, shards[:2], outPath, "spass", false)
	if err != nil {
		t.Fatalf("IdentityCombine: %v", err)
	}
	if recoveredPath == "" {
		t.Error("IdentityCombine returned empty path")
	}
	if _, err := os.Stat(recoveredPath + ".kem.key"); err != nil {
		t.Errorf("combined key file not found at %s: %v", recoveredPath, err)
	}
}

// encodeHex returns a lowercase hex string for the given bytes.
func encodeHex(b []byte) string {
	const hextable = "0123456789abcdef"
	dst := make([]byte, len(b)*2)
	for i, v := range b {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
	return string(dst)
}
