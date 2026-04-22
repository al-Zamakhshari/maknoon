package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBoltRegistry(t *testing.T) {
	tmpDir := t.TempDir()

	// Set home dir for the test
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)

	// Registry needs MaknoonDir existing
	os.MkdirAll(filepath.Join(tmpDir, MaknoonDir), 0700)

	reg, err := NewBoltRegistry()
	if err != nil {
		t.Fatalf("NewBoltRegistry failed: %v", err)
	}
	defer reg.Close()

	// 1. Generate keys for an identity
	kpub, kpriv, spub, spriv, _, npriv, err := GeneratePQKeyPair()
	if err != nil {
		t.Fatalf("GeneratePQKeyPair failed: %v", err)
	}
	defer SafeClear(kpriv)
	defer SafeClear(spriv)
	defer SafeClear(npriv)

	record := &IdentityRecord{
		Handle:    "@tester",
		KEMPubKey: kpub,
		SIGPubKey: spub,
		Timestamp: time.Now(),
	}

	// 2. Sign and Publish
	if err := record.Sign(spriv); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if err := reg.Publish(context.Background(), record); err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// 3. Resolve
	resolved, err := reg.Resolve(context.Background(), "@tester")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if record.Handle != resolved.Handle {
		t.Errorf("Handle mismatch: expected %s, got %s", record.Handle, resolved.Handle)
	}

	// 4. Verify tampering detection
	resolved.Handle = "@hacker" // Local tampering
	if resolved.Verify() {
		t.Error("Verify should fail for tampered handle")
	}

	// 5. Revoke
	proof, _ := SignData([]byte("REVOKE:@tester"), spriv)
	if err := reg.Revoke(context.Background(), "@tester", proof); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	_, err = reg.Resolve(context.Background(), "@tester")
	if err == nil {
		t.Error("Resolve should fail for revoked identity")
	}
}

func TestNostrRegistry(t *testing.T) {
	// 1. Generate keys for an identity
	kpub, kpriv, spub, spriv, npub, npriv, err := GeneratePQKeyPair()
	if err != nil {
		t.Fatalf("GeneratePQKeyPair failed: %v", err)
	}
	defer SafeClear(kpriv)
	defer SafeClear(spriv)
	defer SafeClear(npriv)

	handle := fmt.Sprintf("@nostr:%s", string(npub))
	record := &IdentityRecord{
		Handle:    handle,
		KEMPubKey: kpub,
		SIGPubKey: spub,
		Timestamp: time.Time{},
	}
	if err := record.Sign(spriv); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// 2. Mock Nostr Relay
	// Since we can't easily mock wss:// with go-nostr easily in a few lines without a real listener,
	// we will mock the behavior by manually creating the event and parsing it.

	recordStr, _ := GetCompactDNSRecordString(record)
	dataIdx := strings.Index(recordStr, "data=")
	maknoonData := recordStr[dataIdx+5:]

	metadata := map[string]interface{}{
		"maknoon": maknoonData,
	}
	content, _ := json.Marshal(metadata)

	// Verify our parsing logic works on this content
	var parsedMetadata map[string]interface{}
	if err := json.Unmarshal(content, &parsedMetadata); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	val, ok := parsedMetadata["maknoon"].(string)
	if !ok || val != maknoonData {
		t.Fatalf("Metadata 'maknoon' field mismatch")
	}

	// 3. Verify parseMaknoonTXT can handle it
	parsedRecord, err := parseMaknoonTXT("v=maknoon1;z=1;data=" + val)
	if err != nil {
		t.Fatalf("parseMaknoonTXT failed: %v", err)
	}

	if !bytes.Equal(parsedRecord.KEMPubKey, record.KEMPubKey) {
		t.Error("KEM public key mismatch after roundtrip")
	}
}

func TestMockRegistry(t *testing.T) {
	reg := NewMockRegistry()
	record := &IdentityRecord{Handle: "@mock"}

	if err := reg.Publish(context.Background(), record); err != nil {
		t.Fatalf("Mock Publish failed: %v", err)
	}

	res, err := reg.Resolve(context.Background(), "@mock")
	if err != nil {
		t.Fatalf("Mock Resolve failed: %v", err)
	}
	if res.Handle != "@mock" {
		t.Error("Mock handle mismatch")
	}
}
