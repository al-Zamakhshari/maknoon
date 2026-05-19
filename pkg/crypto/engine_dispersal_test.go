package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// newTestEngine returns a minimal engine wired to a temp home directory.
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	tmp := t.TempDir()
	os.Setenv("HOME", tmp)
	t.Cleanup(func() { os.Unsetenv("HOME") })
	conf := DefaultConfig()
	e, err := NewEngine(&HumanPolicy{}, nil, conf, nil, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestFragmentFileComputesHash(t *testing.T) {
	e := newTestEngine(t)
	tmp := t.TempDir()

	payload := bytes.Repeat([]byte("engine dispersal test "), 50)
	src := filepath.Join(tmp, "input.bin")
	os.WriteFile(src, payload, 0600)

	shardsDir := filepath.Join(tmp, "shards")
	opts := FragmentOptions{
		DataShards:   3,
		ParityShards: 2,
		TargetDir:    shardsDir,
	}
	if err := e.FragmentFile(nil, src, opts); err != nil {
		t.Fatalf("FragmentFile: %v", err)
	}

	// Manifest must exist and carry a correct SHA-256 hash.
	m, err := ReadFragmentManifest(shardsDir)
	if err != nil || m == nil {
		t.Fatalf("ReadFragmentManifest: %v", err)
	}
	want, _ := HashFile(src)
	if m.OriginalHash != want {
		t.Errorf("manifest OriginalHash = %q, want %q", m.OriginalHash, want)
	}
}

func TestFragmentFilePreservesOriginalName(t *testing.T) {
	e := newTestEngine(t)
	tmp := t.TempDir()

	src := filepath.Join(tmp, "secret.pdf")
	os.WriteFile(src, make([]byte, 512), 0600)

	shardsDir := filepath.Join(tmp, "shards")
	opts := FragmentOptions{
		DataShards:   2,
		ParityShards: 1,
		TargetDir:    shardsDir,
	}
	if err := e.FragmentFile(nil, src, opts); err != nil {
		t.Fatalf("FragmentFile: %v", err)
	}

	m, _ := ReadFragmentManifest(shardsDir)
	if m == nil {
		t.Fatal("manifest is nil")
	}
	if m.OriginalName != "secret.pdf" {
		t.Errorf("OriginalName = %q, want %q", m.OriginalName, "secret.pdf")
	}
}

func TestFragmentFileSetsOriginalSize(t *testing.T) {
	e := newTestEngine(t)
	tmp := t.TempDir()

	payload := make([]byte, 1234)
	src := filepath.Join(tmp, "sized.bin")
	os.WriteFile(src, payload, 0600)

	shardsDir := filepath.Join(tmp, "shards")
	opts := FragmentOptions{
		DataShards:   2,
		ParityShards: 1,
		TargetDir:    shardsDir,
	}
	if err := e.FragmentFile(nil, src, opts); err != nil {
		t.Fatalf("FragmentFile: %v", err)
	}

	m, _ := ReadFragmentManifest(shardsDir)
	if m == nil {
		t.Fatal("manifest is nil")
	}
	if m.OriginalSize != 1234 {
		t.Errorf("OriginalSize = %d, want 1234", m.OriginalSize)
	}
}

func TestFragmentFileNonExistent(t *testing.T) {
	e := newTestEngine(t)
	err := e.FragmentFile(nil, "/nonexistent/path/file.bin", FragmentOptions{
		DataShards:   2,
		ParityShards: 1,
		TargetDir:    t.TempDir(),
	})
	if err == nil {
		t.Error("expected error for non-existent input file")
	}
}

func TestReassembleToPath(t *testing.T) {
	e := newTestEngine(t)
	tmp := t.TempDir()

	payload := bytes.Repeat([]byte("reassemble-to-path test "), 20)
	src := filepath.Join(tmp, "input.bin")
	os.WriteFile(src, payload, 0600)

	shardsDir := filepath.Join(tmp, "shards")
	if err := e.FragmentFile(nil, src, FragmentOptions{
		DataShards:   3,
		ParityShards: 2,
		TargetDir:    shardsDir,
	}); err != nil {
		t.Fatalf("FragmentFile: %v", err)
	}

	out := filepath.Join(tmp, "restored.bin")
	if err := e.ReassembleToPath(nil, shardsDir, out, nil); err != nil {
		t.Fatalf("ReassembleToPath: %v", err)
	}

	restored, _ := os.ReadFile(out)
	if !bytes.Equal(restored, payload) {
		t.Error("ReassembleToPath: restored content does not match original")
	}
}

func TestReassembleToPathWithVerify(t *testing.T) {
	e := newTestEngine(t)
	tmp := t.TempDir()

	payload := []byte("verify path round-trip")
	src := filepath.Join(tmp, "v.bin")
	os.WriteFile(src, payload, 0600)

	shardsDir := filepath.Join(tmp, "shards")
	e.FragmentFile(nil, src, FragmentOptions{
		DataShards:   2,
		ParityShards: 1,
		TargetDir:    shardsDir,
	})

	out := filepath.Join(tmp, "v_out.bin")
	e.ReassembleToPath(nil, shardsDir, out, nil)

	if err := VerifyReassembly(shardsDir, out); err != nil {
		t.Errorf("VerifyReassembly after ReassembleToPath: %v", err)
	}
}
