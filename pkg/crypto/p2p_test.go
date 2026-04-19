package crypto

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

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
	_, _, recvFlags, err := ReadHeader(reader, false)
	if err != nil {
		t.Fatal(err)
	}
	reader.Seek(0, 0)

	pr, pw := io.Pipe()
	var dErr error

	done := make(chan bool)
	go func() {
		_, dErr = DecryptStream(reader, pw, passphrase, 1, false)
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
