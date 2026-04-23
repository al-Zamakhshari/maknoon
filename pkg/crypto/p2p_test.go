package crypto

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/al-Zamakhshari/maknoon/pkg/maknooncrypto"
	"github.com/klauspost/compress/zstd"
)

func TestP2PFlowCorruption(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "maknoon-p2p-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	content := []byte("This is a top secret P2P message")
	srcPath := filepath.Join(tmpDir, "secret.txt")
	os.WriteFile(srcPath, content, 0644)

	passphrase := []byte("test-pass")
	opts := Options{
		Passphrase: passphrase,
		Compress:   true, // This is key to reproducing the bug
	}

	// 1. Encrypt to a buffer
	var encrypted bytes.Buffer
	flags, err := Protect(srcPath, nil, &encrypted, opts)
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}

	if flags&FlagCompress == 0 {
		t.Fatal("Expected FlagCompress to be set")
	}

	// 2. Simulate the FIXED receive.go logic
	// Peeking first
	reader := bytes.NewReader(encrypted.Bytes())
	_, _, recvFlags, _, err := ReadHeader(reader, false)
	if err != nil {
		t.Fatal(err)
	}
	reader.Seek(0, 0)

	pr, pw := io.Pipe()
	var dErr error

	done := make(chan bool)
	go func() {
		_, _, dErr = DecryptStream(reader, pw, passphrase, 1, false)
		pw.Close()
		done <- true
	}()

	// Simulating finalizeDecryption from commands/decrypt.go (copied here for the test)
	outBuf := new(bytes.Buffer)

	decReader := io.Reader(pr)
	if recvFlags&FlagCompress != 0 {
		zr, err := zstd.NewReader(pr)
		if err != nil {
			t.Fatalf("Failed to create zstd reader: %v", err)
		}
		decReader = zr
	}
	io.Copy(outBuf, decReader)

	<-done
	if dErr != nil {
		t.Errorf("Decryption failed: %v", dErr)
	}

	if !bytes.Equal(content, outBuf.Bytes()) {
		t.Errorf("Corruption STILL detected!\nExpected: %s\nGot: %s\nFlags: %d",
			string(content), outBuf.String(), recvFlags)
	}
}

func TestP2PDirectoryFlow(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "maknoon-p2p-dir-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. Setup a directory with multiple files
	srcDir := filepath.Join(tmpDir, "source")
	os.Mkdir(srcDir, 0755)
	os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("data1"), 0644)
	os.Mkdir(filepath.Join(srcDir, "subdir"), 0755)
	os.WriteFile(filepath.Join(srcDir, "subdir", "file2.txt"), []byte("data2"), 0644)

	passphrase := []byte("dir-test-pass")
	opts := Options{
		Passphrase: passphrase,
		IsArchive:  true,
		Compress:   true,
	}

	// 2. Encrypt (Simulate 'send')
	var encrypted bytes.Buffer
	flags, err := Protect(srcDir, nil, &encrypted, opts)
	if err != nil {
		t.Fatalf("Protect failed: %v", err)
	}

	if flags&FlagArchive == 0 {
		t.Fatal("Expected FlagArchive to be set")
	}

	// 3. Decrypt and Restore (Simulate 'receive')
	// Peek flags first (as per our fix)
	reader := bytes.NewReader(encrypted.Bytes())
	_, _, recvFlags, _, err := ReadHeader(reader, false)
	if err != nil {
		t.Fatal(err)
	}
	reader.Seek(0, 0)

	restoredDir := filepath.Join(tmpDir, "restored")

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		_, _, dErr := DecryptStream(reader, pw, passphrase, 1, false)
		if dErr != nil {
			pw.CloseWithError(dErr)
		}
	}()

	// Simulating finalizeDecryption with directory extraction
	decReader := io.Reader(pr)
	if recvFlags&FlagCompress != 0 {
		zr, _ := zstd.NewReader(pr)
		decReader = zr
	}

	if err := ExtractArchive(decReader, restoredDir); err != nil {
		t.Fatalf("Extraction failed: %v", err)
	}

	// 4. Verify results
	// Note: ExtractArchive puts files relative to outPath.
	// Our source was "source", so it should be in restoredDir/source/...
	f1, _ := os.ReadFile(filepath.Join(restoredDir, "source", "file1.txt"))
	if string(f1) != "data1" {
		t.Errorf("File1 mismatch: %s", string(f1))
	}
	f2, _ := os.ReadFile(filepath.Join(restoredDir, "source", "subdir", "file2.txt"))
	if string(f2) != "data2" {
		t.Errorf("File2 mismatch: %s", string(f2))
	}
}

func TestP2PTextTransfer(t *testing.T) {
	// 1. Setup text and passphrase
	content := "top-secret-p2p-text"
	passphrase := []byte("text-test-pass")

	// 2. Encrypt to memory buffer (Simulate 'send --text')
	var encrypted bytes.Buffer
	opts := Options{
		Passphrase: passphrase,
		Compress:   true,
	}
	// Use inputName as a label since we are using a reader
	_, err := Protect("text", strings.NewReader(content), &encrypted, opts)
	if err != nil {
		t.Fatalf("Protect text failed: %v", err)
	}

	// 3. Decrypt from memory buffer (Simulate 'receive')
	var decrypted bytes.Buffer
	// Symmetric flow
	recvFlags, _, err := DecryptStream(&encrypted, &decrypted, passphrase, 1, false)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Finalize (Decompress)
	// Create a temp file path instead of "-" to capture output if it's not stdout
	// Actually, FinalizeRestoration needs a way to write to a custom buffer.
	// For now, let's use a temporary file.
	outPath := filepath.Join(t.TempDir(), "out.txt")
	if err := FinalizeRestoration(&decrypted, nil, recvFlags, outPath, nil); err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	restored, _ := os.ReadFile(outPath)
	if string(restored) != content {
		t.Errorf("Decrypted text mismatch. Expected: %s, Got: %q", content, string(restored))
	}
}

func TestP2PAsymmetric(t *testing.T) {
	// 1. Setup Identities
	priv, pub, err := maknooncrypto.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := pub.Bytes()
	privBytes, _ := priv.Bytes()

	content := "asymmetric-p2p-payload"

	// 2. Encrypt for recipient (Simulate 'send --public-key')
	var encrypted bytes.Buffer
	opts := Options{
		PublicKeys: [][]byte{pubBytes},
		Compress:   true,
	}
	_, err = Protect("asym", strings.NewReader(content), &encrypted, opts)
	if err != nil {
		t.Fatalf("Protect asym failed: %v", err)
	}

	// 3. Decrypt with recipient's private key (Simulate 'receive')
	// Peek at header first (standard pattern)
	reader := bytes.NewReader(encrypted.Bytes())
	magic, _, _, _, err := ReadHeader(reader, false)
	if err != nil {
		t.Fatal(err)
	}
	if magic != MagicHeaderAsym {
		t.Fatalf("Expected magic %s, got %s", MagicHeaderAsym, magic)
	}
	reader.Seek(0, 0)

	var decrypted bytes.Buffer
	// Asymmetric flow
	recvFlags, _, err := DecryptStreamWithPrivateKey(reader, &decrypted, privBytes, 1, false)
	if err != nil {
		t.Fatalf("Asymmetric decryption failed: %v", err)
	}

	// Finalize (Decompress)
	outPath := filepath.Join(t.TempDir(), "out_asym.txt")
	if err := FinalizeRestoration(&decrypted, nil, recvFlags, outPath, nil); err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}

	restored, _ := os.ReadFile(outPath)
	if string(restored) != content {
		t.Errorf("Decrypted content mismatch. Expected: %s, Got: %q", content, string(restored))
	}
}
