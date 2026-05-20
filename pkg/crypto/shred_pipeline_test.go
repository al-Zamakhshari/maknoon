package crypto

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// --- shred / SecureDelete ---

func TestSecureDeleteStream(t *testing.T) {
	e := engineForVault(t)
	tmp := t.TempDir()

	// Create a file with sensitive content.
	f := filepath.Join(tmp, "shred_stream.bin")
	os.WriteFile(f, bytes.Repeat([]byte("secret"), 1000), 0600)

	if err := e.SecureDeleteStream(f); err != nil {
		t.Fatalf("SecureDeleteStream: %v", err)
	}
	if _, err := os.Stat(f); err == nil {
		t.Error("file should not exist after SecureDeleteStream")
	}
}

func TestSecureDeleteDirectory(t *testing.T) {
	e := engineForVault(t)
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "shred_dir")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "a.bin"), []byte("data a"), 0600)
	os.WriteFile(filepath.Join(dir, "b.bin"), []byte("data b"), 0600)

	if err := e.SecureDelete(dir); err != nil {
		t.Fatalf("SecureDelete directory: %v", err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("directory should not exist after SecureDelete")
	}
}

func TestSecureDeleteNonExistent(t *testing.T) {
	e := engineForVault(t)
	// Non-existent path should return an error or silently succeed.
	err := e.SecureDelete("/nonexistent/path/file.bin")
	// Either outcome is acceptable — just must not panic.
	_ = err
}

// --- pipeline.go: Inspect ---

func TestPipelineInspectSymmetric(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("inspect-pass")
	plain := []byte("pipeline inspect test")

	var ct bytes.Buffer
	e.Protect(nil, "p.bin", bytes.NewReader(plain), &ct, Options{Passphrase: pass})

	// Inspect reads the header without decrypting.
	info, err := e.Inspect(nil, bytes.NewReader(ct.Bytes()), false)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info == nil {
		t.Fatal("Inspect returned nil")
	}
}

// --- compression (ZstdTransformer) ---

func TestZstdCompressDecompressEmpty(t *testing.T) {
	enc := &ZstdTransformer{IsDecompress: false}
	var compressed bytes.Buffer
	if err := enc.Transform(bytes.NewReader([]byte{}), &compressed); err != nil {
		t.Fatalf("compress empty: %v", err)
	}

	dec := &ZstdTransformer{IsDecompress: true}
	var out bytes.Buffer
	if err := dec.Transform(bytes.NewReader(compressed.Bytes()), &out); err != nil {
		t.Fatalf("decompress empty: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("expected empty output, got %d bytes", out.Len())
	}
}

func TestZstdLargePayload(t *testing.T) {
	// 1 MB compressible payload.
	payload := bytes.Repeat([]byte("compressible data block "), 40000)

	var compressed bytes.Buffer
	enc := &ZstdTransformer{}
	enc.Transform(bytes.NewReader(payload), &compressed)

	var out bytes.Buffer
	dec := &ZstdTransformer{IsDecompress: true}
	dec.Transform(bytes.NewReader(compressed.Bytes()), &out)

	if !bytes.Equal(out.Bytes(), payload) {
		t.Error("large payload zstd round-trip mismatch")
	}
}

// --- AEADTransformer with private key path ---

func TestAEADTransformerPrivKeyEncryptDecrypt(t *testing.T) {
	kemPub, kemPriv, _, _, _ := GeneratePQKeyPair(1)
	defer SafeClear(kemPriv)

	plain := []byte("private key aead transformer test")
	profile := DefaultProfile()

	// Encrypt to public key.
	var ct bytes.Buffer
	enc := &AEADTransformer{
		RecipientPK: [][]byte{kemPub},
		Profile:     profile,
		Concurrency: 1,
	}
	if err := enc.Transform(bytes.NewReader(plain), &ct); err != nil {
		t.Fatalf("encrypt with public key: %v", err)
	}

	// Decrypt with private key. RecipientPK path uses FlagStealth, so stealth=true.
	var out bytes.Buffer
	dec := &AEADTransformer{
		PrivKey:     kemPriv,
		Profile:     profile,
		Concurrency: 1,
		IsDecrypt:   true,
		Stealth:     true,
	}
	if err := dec.Transform(bytes.NewReader(ct.Bytes()), &out); err != nil {
		t.Fatalf("decrypt with private key: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Error("private key AEAD round-trip mismatch")
	}
}

// --- TarTransformer (archive path) ---

func TestTarTransformerExtractDoesNotPanic(t *testing.T) {
	// TarTransformer.Transform with IsExtract=true and invalid reader should
	// return an error rather than panic.
	tt := &TarTransformer{BaseDir: t.TempDir(), IsExtract: true}
	err := tt.Transform(bytes.NewReader([]byte("not a tar")), io.Discard)
	// Error is expected — just must not panic.
	_ = err
}

func TestTarTransformerArchiveNoOp(t *testing.T) {
	// TarTransformer archive direction (IsExtract=false) is a no-op in Transform.
	tt := &TarTransformer{IsExtract: false}
	err := tt.Transform(bytes.NewReader([]byte("data")), io.Discard)
	if err != nil {
		t.Errorf("TarTransformer archive no-op returned error: %v", err)
	}
}

// --- containedPath (package-level, tested indirectly via SecureDelete) ---

func TestContainedPathRejectsTraversal(t *testing.T) {
	tmp := t.TempDir()
	_, err := containedPath("../../etc/passwd", tmp)
	if err == nil {
		t.Error("expected error for path traversal")
	}
}

func TestContainedPathAcceptsValid(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "valid.bin")
	os.WriteFile(f, []byte("ok"), 0600)

	p, err := containedPath(f, tmp)
	if err != nil {
		t.Fatalf("containedPath valid: %v", err)
	}
	if p == "" {
		t.Error("containedPath returned empty string for valid path")
	}
}
