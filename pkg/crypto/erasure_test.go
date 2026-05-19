package crypto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestErasureCodingE2E(t *testing.T) {
	tmpDir := t.TempDir()
	data := []byte("RAID-for-Privacy: Fragmented data survivability test payload.")

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

	// Sabotage 2 of 5 shards — 3 data shards remain, still reconstructable.
	os.Remove(filepath.Join(tmpDir, "shards", "shard_000.maknf"))
	os.Remove(filepath.Join(tmpDir, "shards", "shard_004.maknf"))

	var buf bytes.Buffer
	if err := ReassembleFragments(filepath.Join(tmpDir, "shards"), &buf, nil); err != nil {
		t.Fatalf("ReassembleFragments failed: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Errorf("recovered data mismatch\ngot:  %s\nwant: %s", buf.String(), string(data))
	}
}

func TestErasureIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	data := []byte("Forensic Integrity Test: Every block is signed.")

	_, _, sigPub, sigPriv, _ := GeneratePQKeyPair(1)

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

	shardPath := filepath.Join(tmpDir, "shards", "shard_001.maknf")
	f, _ := os.OpenFile(shardPath, os.O_RDWR, 0644)
	f.WriteAt([]byte("CORRUPT"), 20)
	f.Close()

	var buf bytes.Buffer
	err := ReassembleFragments(filepath.Join(tmpDir, "shards"), &buf, sigPub)
	if err == nil {
		t.Fatal("expected ReassembleFragments to fail due to corruption")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("integrity failure")) {
		t.Errorf("expected 'integrity failure' error, got: %v", err)
	}
}

// --- V2 / V3 Header Tests ---

func TestFragmentV2Header(t *testing.T) {
	tmpDir := t.TempDir()
	data := make([]byte, 256)

	_, _, _, sigPriv, _ := GeneratePQKeyPair(1)

	opts := FragmentOptions{
		DataShards:   2,
		ParityShards: 1,
		TargetDir:    filepath.Join(tmpDir, "shards"),
		OriginalSize: int64(len(data)),
		SigningKey:   sigPriv, // triggers V2
	}
	fw, err := NewFragmentWriter(opts)
	if err != nil {
		t.Fatalf("NewFragmentWriter: %v", err)
	}
	fw.Write(data)
	fw.Close()

	// Read raw header from shard_000.
	raw, err := os.ReadFile(filepath.Join(tmpDir, "shards", "shard_000.maknf"))
	if err != nil {
		t.Fatalf("reading shard: %v", err)
	}
	if len(raw) < headerSizeV2 {
		t.Fatalf("shard too small for V2 header: %d bytes", len(raw))
	}
	if string(raw[:4]) != FragmentMagic {
		t.Errorf("magic mismatch: got %q", string(raw[:4]))
	}
	if raw[4] != VersionV2 {
		t.Errorf("expected version %d, got %d", VersionV2, raw[4])
	}
	sigSize := binary.LittleEndian.Uint16(raw[16:18])
	if sigSize == 0 {
		t.Error("expected non-zero SigSize in V2 header")
	}
}

func TestFragmentV3Header(t *testing.T) {
	tmpDir := t.TempDir()
	data := make([]byte, 512)
	const customChunk = 128 * 1024 // 128 KB

	opts := FragmentOptions{
		DataShards:     2,
		ParityShards:   1,
		TargetDir:      filepath.Join(tmpDir, "shards"),
		OriginalSize:   int64(len(data)),
		ShardChunkSize: customChunk,
	}
	fw, err := NewFragmentWriter(opts)
	if err != nil {
		t.Fatalf("NewFragmentWriter: %v", err)
	}
	fw.Write(data)
	fw.Close()

	raw, err := os.ReadFile(filepath.Join(tmpDir, "shards", "shard_000.maknf"))
	if err != nil {
		t.Fatalf("reading shard: %v", err)
	}
	if len(raw) < headerSizeV3 {
		t.Fatalf("shard too small for V3 header: %d bytes", len(raw))
	}
	if raw[4] != VersionV3 {
		t.Errorf("expected version %d, got %d", VersionV3, raw[4])
	}
	stored := int(binary.LittleEndian.Uint32(raw[18:22]))
	if stored != customChunk {
		t.Errorf("stored ChunkSize = %d, want %d", stored, customChunk)
	}
}

func TestFragmentDefaultChunkProducesV2(t *testing.T) {
	// No custom chunk size → should write V2, not V3.
	tmpDir := t.TempDir()
	opts := FragmentOptions{
		DataShards:   2,
		ParityShards: 1,
		TargetDir:    filepath.Join(tmpDir, "shards"),
		OriginalSize: 64,
	}
	fw, _ := NewFragmentWriter(opts)
	fw.Write(make([]byte, 64))
	fw.Close()

	raw, _ := os.ReadFile(filepath.Join(tmpDir, "shards", "shard_000.maknf"))
	if raw[4] != VersionV2 {
		t.Errorf("default chunk size should produce V2 header, got version %d", raw[4])
	}
}

// --- Manifest Tests ---

func TestFragmentManifestRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	payload := []byte("manifest round-trip test payload for Maknoon")
	src := filepath.Join(tmpDir, "input.bin")
	os.WriteFile(src, payload, 0600)

	origHash, _ := HashFile(src)
	opts := FragmentOptions{
		DataShards:   3,
		ParityShards: 2,
		TargetDir:    filepath.Join(tmpDir, "shards"),
		OriginalSize: int64(len(payload)),
		OriginalName: "input.bin",
		OriginalHash: origHash,
	}
	fw, err := NewFragmentWriter(opts)
	if err != nil {
		t.Fatalf("NewFragmentWriter: %v", err)
	}
	fw.Write(payload)
	fw.Close()

	m, err := ReadFragmentManifest(filepath.Join(tmpDir, "shards"))
	if err != nil {
		t.Fatalf("ReadFragmentManifest: %v", err)
	}
	if m == nil {
		t.Fatal("manifest is nil")
	}
	if m.OriginalHash != origHash {
		t.Errorf("OriginalHash mismatch: got %s, want %s", m.OriginalHash, origHash)
	}
	if m.OriginalName != "input.bin" {
		t.Errorf("OriginalName = %q, want %q", m.OriginalName, "input.bin")
	}
	if m.DataShards != 3 || m.ParityShards != 2 {
		t.Errorf("shard counts wrong: data=%d parity=%d", m.DataShards, m.ParityShards)
	}
	if m.TotalShards != 5 {
		t.Errorf("TotalShards = %d, want 5", m.TotalShards)
	}
	if len(m.Shards) != 5 {
		t.Errorf("Shards list length = %d, want 5", len(m.Shards))
	}
}

func TestFragmentManifestChunkSizeStored(t *testing.T) {
	tmpDir := t.TempDir()
	const customChunk = 256 * 1024

	opts := FragmentOptions{
		DataShards:     2,
		ParityShards:   1,
		TargetDir:      filepath.Join(tmpDir, "shards"),
		OriginalSize:   128,
		ShardChunkSize: customChunk,
	}
	fw, _ := NewFragmentWriter(opts)
	fw.Write(make([]byte, 128))
	fw.Close()

	m, err := ReadFragmentManifest(filepath.Join(tmpDir, "shards"))
	if err != nil || m == nil {
		t.Fatalf("ReadFragmentManifest: %v", err)
	}
	if m.ShardChunkSize != customChunk {
		t.Errorf("manifest ShardChunkSize = %d, want %d", m.ShardChunkSize, customChunk)
	}
}

func TestFragmentManifestDefaultChunkNotStored(t *testing.T) {
	// Default chunk size should be omitted from manifest (zero value = use default).
	tmpDir := t.TempDir()
	opts := FragmentOptions{
		DataShards:   2,
		ParityShards: 1,
		TargetDir:    filepath.Join(tmpDir, "shards"),
		OriginalSize: 64,
	}
	fw, _ := NewFragmentWriter(opts)
	fw.Write(make([]byte, 64))
	fw.Close()

	m, _ := ReadFragmentManifest(filepath.Join(tmpDir, "shards"))
	if m.ShardChunkSize != 0 {
		t.Errorf("expected ShardChunkSize=0 for default, got %d", m.ShardChunkSize)
	}
}

func TestFragmentManifestCustomPath(t *testing.T) {
	tmpDir := t.TempDir()
	customManifest := filepath.Join(tmpDir, "my-manifest.json")

	opts := FragmentOptions{
		DataShards:   2,
		ParityShards: 1,
		TargetDir:    filepath.Join(tmpDir, "shards"),
		OriginalSize: 64,
		ManifestPath: customManifest,
	}
	fw, _ := NewFragmentWriter(opts)
	fw.Write(make([]byte, 64))
	fw.Close()

	// Manifest at custom path must exist.
	if _, err := os.Stat(customManifest); err != nil {
		t.Errorf("custom manifest not written: %v", err)
	}
	// Default path must NOT exist.
	if _, err := os.Stat(filepath.Join(tmpDir, "shards", "manifest.json")); err == nil {
		t.Error("default manifest written even though ManifestPath was set")
	}
}

func TestReadFragmentManifestAbsent(t *testing.T) {
	m, err := ReadFragmentManifest(t.TempDir())
	if err != nil {
		t.Errorf("expected nil error for absent manifest, got: %v", err)
	}
	if m != nil {
		t.Errorf("expected nil manifest for absent file, got: %+v", m)
	}
}

func TestReadFragmentManifestCorrupt(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("not valid json{{"), 0600)

	_, err := ReadFragmentManifest(dir)
	if err == nil {
		t.Error("expected error for corrupt manifest JSON, got nil")
	}
}

// --- VerifyReassembly Tests ---

func TestVerifyReassemblyPass(t *testing.T) {
	tmpDir := t.TempDir()
	payload := []byte("verification payload — byte perfect")
	src := filepath.Join(tmpDir, "src.bin")
	os.WriteFile(src, payload, 0600)

	origHash, _ := HashFile(src)
	shardsDir := filepath.Join(tmpDir, "shards")
	opts := FragmentOptions{
		DataShards:   2,
		ParityShards: 1,
		TargetDir:    shardsDir,
		OriginalSize: int64(len(payload)),
		OriginalHash: origHash,
	}
	fw, _ := NewFragmentWriter(opts)
	fw.Write(payload)
	fw.Close()

	out := filepath.Join(tmpDir, "restored.bin")
	f, _ := os.Create(out)
	ReassembleFragments(shardsDir, f, nil)
	f.Close()

	if err := VerifyReassembly(shardsDir, out); err != nil {
		t.Errorf("VerifyReassembly failed unexpectedly: %v", err)
	}
}

func TestVerifyReassemblyFail(t *testing.T) {
	tmpDir := t.TempDir()
	payload := []byte("original payload")
	src := filepath.Join(tmpDir, "src.bin")
	os.WriteFile(src, payload, 0600)

	origHash, _ := HashFile(src)
	shardsDir := filepath.Join(tmpDir, "shards")
	opts := FragmentOptions{
		DataShards:   2,
		ParityShards: 1,
		TargetDir:    shardsDir,
		OriginalSize: int64(len(payload)),
		OriginalHash: origHash,
	}
	fw, _ := NewFragmentWriter(opts)
	fw.Write(payload)
	fw.Close()

	// Write tampered output.
	out := filepath.Join(tmpDir, "tampered.bin")
	os.WriteFile(out, []byte("tampered content"), 0600)

	err := VerifyReassembly(shardsDir, out)
	if err == nil {
		t.Error("expected VerifyReassembly to fail for tampered output")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("integrity check FAILED")) {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestVerifyReassemblyNoManifest(t *testing.T) {
	// No manifest → VerifyReassembly returns nil (backward compat).
	out := filepath.Join(t.TempDir(), "out.bin")
	os.WriteFile(out, []byte("anything"), 0600)
	if err := VerifyReassembly(t.TempDir(), out); err != nil {
		t.Errorf("expected nil when no manifest, got: %v", err)
	}
}

// --- effectiveChunkSize Tests ---

func TestEffectiveChunkSize(t *testing.T) {
	tests := []struct {
		input int
		want  int
	}{
		{0, ChunkSize},      // default
		{-1, ChunkSize},     // negative → default
		{100, MinChunkSize}, // below min → clamped to min
		{MinChunkSize, MinChunkSize},
		{MaxChunkSize, MaxChunkSize},
		{MaxChunkSize + 1, MaxChunkSize}, // above max → clamped to max
		{128 * 1024, 128 * 1024},         // exact value preserved
	}
	for _, tt := range tests {
		opts := FragmentOptions{ShardChunkSize: tt.input}
		got := opts.effectiveChunkSize()
		if got != tt.want {
			t.Errorf("effectiveChunkSize(%d) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

// --- V3 Reassembly round-trip Tests ---

func TestReassembleV3ChunkSize(t *testing.T) {
	tmpDir := t.TempDir()
	// Use data larger than one chunk to exercise multi-block path.
	data := make([]byte, 3*MinChunkSize+7)
	for i := range data {
		data[i] = byte(i % 251)
	}

	shardsDir := filepath.Join(tmpDir, "shards")
	opts := FragmentOptions{
		DataShards:     3,
		ParityShards:   2,
		TargetDir:      shardsDir,
		OriginalSize:   int64(len(data)),
		ShardChunkSize: MinChunkSize,
	}
	fw, err := NewFragmentWriter(opts)
	if err != nil {
		t.Fatalf("NewFragmentWriter: %v", err)
	}
	fw.Write(data)
	fw.Close()

	var buf bytes.Buffer
	if err := ReassembleFragments(shardsDir, &buf, nil); err != nil {
		t.Fatalf("ReassembleFragments: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Error("V3 reassembled data does not match original")
	}
}

// --- HashFile Tests ---

func TestHashFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.bin")
	os.WriteFile(f, []byte("hash me"), 0600)

	h1, err := HashFile(f)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	if len(h1) != 64 {
		t.Errorf("expected 64-char hex hash, got len=%d", len(h1))
	}

	// Deterministic: same file → same hash.
	h2, _ := HashFile(f)
	if h1 != h2 {
		t.Error("HashFile is not deterministic")
	}
}

func TestHashFileNotFound(t *testing.T) {
	_, err := HashFile("/nonexistent/path/file.bin")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// --- Manifest JSON field names (regression guard) ---

func TestManifestJSONFields(t *testing.T) {
	m := FragmentManifest{
		Version:        1,
		OriginalName:   "test.bin",
		OriginalSize:   1024,
		OriginalHash:   "abc123",
		DataShards:     3,
		ParityShards:   2,
		TotalShards:    5,
		Signed:         false,
		ShardChunkSize: 131072,
		Shards:         []ShardInfo{{Index: 0, Filename: "shard_000.maknf"}},
	}
	b, _ := json.Marshal(m)
	s := string(b)
	for _, field := range []string{
		"original_name", "original_size", "original_hash",
		"data_shards", "parity_shards", "total_shards",
		"shard_chunk_size",
	} {
		if !bytes.Contains(b, []byte(`"`+field+`"`)) {
			t.Errorf("manifest JSON missing field %q in: %s", field, s)
		}
	}
}
