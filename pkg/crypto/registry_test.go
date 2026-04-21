package crypto

import (
	"context"
	"os"
	"path/filepath"
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
	kpub, kpriv, spub, spriv, err := GeneratePQKeyPair()
	if err != nil {
		t.Fatalf("GeneratePQKeyPair failed: %v", err)
	}
	defer SafeClear(kpriv)
	defer SafeClear(spriv)

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

	if resolved.Handle != record.Handle {
		t.Errorf("Handle mismatch: expected %s, got %s", record.Handle, resolved.Handle)
	}

	// 4. Verify tampering detection
	resolved.Handle = "@hacker" // Local tampering (doesn't happen in Resolve but good for Verify test)
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
