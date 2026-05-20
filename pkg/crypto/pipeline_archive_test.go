package crypto

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// --- wrapWithArchiver + ExtractArchive end-to-end via Protect/Unprotect ---

func TestArchiveRoundTripViaPipeline(t *testing.T) {
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "hello.txt"), []byte("world"), 0600)
	sub := filepath.Join(src, "sub")
	os.MkdirAll(sub, 0700)
	os.WriteFile(filepath.Join(sub, "nested.txt"), []byte("nested"), 0600)

	e := engineForVault(t)
	pass := []byte("archive-roundtrip")

	var ct bytes.Buffer
	if _, err := e.Protect(nil, src, nil, &ct, Options{Passphrase: pass, IsArchive: true}); err != nil {
		t.Fatalf("Protect directory archive: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatal("encrypted archive is empty")
	}

	dst := t.TempDir()
	if _, err := e.Unprotect(nil, bytes.NewReader(ct.Bytes()), nil, dst, Options{Passphrase: pass}); err != nil {
		t.Fatalf("Unprotect archive: %v", err)
	}

	// wrapWithArchiver uses filepath.Dir(src) as base, so entries sit under basename(src).
	srcBase := filepath.Base(src)
	gotHello, err := os.ReadFile(filepath.Join(dst, srcBase, "hello.txt"))
	if err != nil {
		t.Fatalf("hello.txt not restored: %v", err)
	}
	if string(gotHello) != "world" {
		t.Errorf("hello.txt = %q, want %q", gotHello, "world")
	}
	gotNested, err := os.ReadFile(filepath.Join(dst, srcBase, "sub", "nested.txt"))
	if err != nil {
		t.Fatalf("sub/nested.txt not restored: %v", err)
	}
	if string(gotNested) != "nested" {
		t.Errorf("sub/nested.txt = %q, want %q", gotNested, "nested")
	}
}

// --- openSourceReader: path traversal rejection ---

func TestOpenSourceReaderPathTraversal(t *testing.T) {
	_, _, err := openSourceReader("../../../etc/passwd", nil, Options{})
	if err == nil {
		t.Error("expected error for path traversal in openSourceReader")
	}
}

// --- ExtractArchive: directory entries ---

func TestExtractArchiveWithDirectory(t *testing.T) {
	content := []byte("file inside subdir")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "subdir/", Mode: 0750})
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "subdir/file.txt", Size: int64(len(content)), Mode: 0600})
	tw.Write(content)
	tw.Close()

	dst := t.TempDir()
	if err := ExtractArchive(bytes.NewReader(buf.Bytes()), dst); err != nil {
		t.Fatalf("ExtractArchive with directory entry: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "subdir", "file.txt"))
	if err != nil {
		t.Fatalf("file.txt not found after extraction: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content = %q, want %q", got, content)
	}
}

// --- ExtractArchive: path traversal in tar entry name ---

func TestExtractArchivePathTraversal(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "../../../etc/evil",
		Size:     4,
		Mode:     0600,
	})
	tw.Write([]byte("evil"))
	tw.Close()

	err := ExtractArchive(bytes.NewReader(buf.Bytes()), t.TempDir())
	if err == nil {
		t.Fatal("expected error for path traversal in tar entry")
	}
	var pv *ErrPolicyViolation
	if !As(err, &pv) {
		t.Errorf("expected ErrPolicyViolation, got %T: %v", err, err)
	}
}

// --- ExtractArchive: malformed tar ---

func TestExtractArchiveBrokenHeader(t *testing.T) {
	err := ExtractArchive(bytes.NewReader([]byte("not a tar stream at all")), t.TempDir())
	if err == nil {
		t.Error("expected error for malformed tar input")
	}
}

// --- FinalizeRestoration: compress-only (FlagCompress, write to io.Writer) ---

func TestFinalizeRestorationCompressOnly(t *testing.T) {
	plain := []byte("finalize restoration: compressed output")
	var compressed bytes.Buffer
	if err := CompressStream(bytes.NewReader(plain), &compressed); err != nil {
		t.Fatalf("CompressStream: %v", err)
	}

	e := NewStreamEngine(nil)
	var out bytes.Buffer
	if err := e.FinalizeRestoration(nil, bytes.NewReader(compressed.Bytes()), &out, FlagCompress, "", slog.Default()); err != nil {
		t.Fatalf("FinalizeRestoration compress-only: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Errorf("decompressed = %q, want %q", out.Bytes(), plain)
	}
}

// --- FinalizeRestoration: FlagCompress|FlagArchive → decompress then extract ---

func TestFinalizeRestorationCompressedArchive(t *testing.T) {
	content := []byte("compressed archive restoration")
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "restored.txt", Size: int64(len(content)), Mode: 0600})
	tw.Write(content)
	tw.Close()

	var compressed bytes.Buffer
	if err := CompressStream(bytes.NewReader(tarBuf.Bytes()), &compressed); err != nil {
		t.Fatalf("CompressStream: %v", err)
	}

	e := NewStreamEngine(nil)
	dst := t.TempDir()
	if err := e.FinalizeRestoration(nil, bytes.NewReader(compressed.Bytes()), nil, FlagCompress|FlagArchive, dst, slog.Default()); err != nil {
		t.Fatalf("FinalizeRestoration compress+archive: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "restored.txt"))
	if err != nil {
		t.Fatalf("restored.txt not found: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content = %q, want %q", got, content)
	}
}

// --- FinalizeRestoration: no flags, write to file path ---

func TestFinalizeRestorationToPath(t *testing.T) {
	plain := []byte("plain output to path")
	outFile := filepath.Join(t.TempDir(), "output.bin")

	e := NewStreamEngine(nil)
	if err := e.FinalizeRestoration(nil, bytes.NewReader(plain), nil, 0, outFile, slog.Default()); err != nil {
		t.Fatalf("FinalizeRestoration to path: %v", err)
	}
	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output file not found: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("file content = %q, want %q", got, plain)
	}
}

// --- FinalizeRestoration: path traversal in outPath ---

func TestFinalizeRestorationPathTraversal(t *testing.T) {
	e := NewStreamEngine(nil)
	err := e.FinalizeRestoration(nil, bytes.NewReader([]byte("data")), nil, 0, "../escape/path.txt", slog.Default())
	if err == nil {
		t.Error("expected error for path traversal in outPath")
	}
}

// --- dispatchEncrypt: session key branch ---

func TestProtectUnprotectSessionKey(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	plain := []byte("session key encryption round-trip")

	var ct bytes.Buffer
	if _, err := Protect("test.bin", bytes.NewReader(plain), &ct, Options{SessionKey: key}); err != nil {
		t.Fatalf("Protect with SessionKey: %v", err)
	}

	var out bytes.Buffer
	if _, err := Unprotect(bytes.NewReader(ct.Bytes()), &out, "", Options{SessionKey: key}); err != nil {
		t.Fatalf("Unprotect with SessionKey: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Error("session key round-trip mismatch")
	}
}
