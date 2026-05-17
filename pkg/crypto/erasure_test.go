package crypto

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestErasureCodingE2E(t *testing.T) {
	tmpDir := t.TempDir()
	data := []byte("RAID-for-Privacy: Fragmented data survivability test payload.")

	// 1. Fragment
	fOpts := FragmentOptions{
		DataShards:   3,
		ParityShards: 2,
		TargetDir:    filepath.Join(tmpDir, "shards"),
		OriginalSize: int64(len(data)),
	}

	fw, err := NewFragmentWriter(fOpts)
	if err != nil {
		t.Fatalf("NewFragmentWriter failed: %v", err)
	}

	if _, err := io.Copy(fw, bytes.NewReader(data)); err != nil {
		t.Fatalf("Fragment writing failed: %v", err)
	}
	fw.Close()

	// 2. Sabotage shards (2 out of 5, should still work since 3 data shards exist)
	os.Remove(filepath.Join(tmpDir, "shards", "shard_000.maknf"))
	os.Remove(filepath.Join(tmpDir, "shards", "shard_004.maknf"))

	// 3. Reassemble
	var buf bytes.Buffer
	if err := ReassembleFragments(filepath.Join(tmpDir, "shards"), &buf, nil); err != nil {
		t.Fatalf("ReassembleFragments failed: %v", err)
	}

	if !bytes.Equal(buf.Bytes(), data) {
		t.Errorf("Recovered data mismatch.\nGot:  %s\nWant: %s", buf.String(), string(data))
	}
}

func TestErasureIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	data := []byte("Forensic Integrity Test: Every block is signed.")

	_, _, sigPub, sigPriv, _ := GeneratePQKeyPair(1)

	// 1. Fragment with signing
	fOpts := FragmentOptions{
		DataShards:   2,
		ParityShards: 1,
		TargetDir:    filepath.Join(tmpDir, "shards"),
		OriginalSize: int64(len(data)),
		SigningKey:   sigPriv,
	}

	fw, _ := NewFragmentWriter(fOpts)
	fw.Write(data)
	fw.Close()

	// 2. Corrupt a shard
	shardPath := filepath.Join(tmpDir, "shards", "shard_001.maknf")
	f, _ := os.OpenFile(shardPath, os.O_RDWR, 0644)
	f.WriteAt([]byte("CORRUPT"), 20) // Overwrite part of signature
	f.Close()

	// 3. Reassemble (should fail)
	var buf bytes.Buffer
	err := ReassembleFragments(filepath.Join(tmpDir, "shards"), &buf, sigPub)
	if err == nil {
		t.Fatal("Expected ReassembleFragments to fail due to corruption, but it succeeded")
	}

	if !bytes.Contains([]byte(err.Error()), []byte("integrity failure")) {
		t.Errorf("Expected integrity failure error, got: %v", err)
	}
}
