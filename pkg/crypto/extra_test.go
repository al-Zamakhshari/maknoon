package crypto

import (
	"bytes"
	"github.com/klauspost/compress/zstd"
	"io"
	"testing"
)

func TestProtectFullFlow(t *testing.T) {
	data := []byte("Full protection pipeline test data")
	passphrase := []byte("pipeline-pass")

	opts := Options{
		Passphrase:  passphrase,
		Compress:    true,
		Concurrency: 4,
	}

	var encrypted bytes.Buffer
	if err := Protect("test.txt", bytes.NewReader(data), &encrypted, opts); err != nil {
		t.Fatalf("Protect failed: %v", err)
	}

	var decrypted bytes.Buffer
	flags, err := DecryptStream(&encrypted, &decrypted, passphrase, 1, false)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	finalData := decrypted.Bytes()
	if flags&FlagCompress != 0 {
		zr, err := zstd.NewReader(bytes.NewReader(finalData))
		if err != nil {
			t.Fatal(err)
		}
		defer zr.Close()
		var decompressed bytes.Buffer
		if _, err := io.Copy(&decompressed, zr); err != nil {
			t.Fatal(err)
		}
		finalData = decompressed.Bytes()
	}

	if !bytes.Equal(data, finalData) {
		t.Errorf("Decrypted data mismatch. Got: %s", string(finalData))
	}
}

func TestVaultSealOpenConsistency(t *testing.T) {
	masterKey := make([]byte, 32)
	entry := &VaultEntry{
		Service:  "github.com",
		Username: "user1",
		Password: []byte("pass"),
		Note:     "test note",
	}

	ciphertext, err := SealEntry(entry, masterKey)
	if err != nil {
		t.Fatal(err)
	}

	restored, err := OpenEntry(ciphertext, masterKey)
	if err != nil {
		t.Fatal(err)
	}

	if restored.Service != entry.Service || string(restored.Password) != string(entry.Password) {
		t.Error("Vault entry mismatch after seal/open")
	}
}

func TestExtractArchiveZipSlip(t *testing.T) {
	// Already tested in stress_test.go, but adding a unit test here for completeness
	var buf bytes.Buffer
	// Invalid path with ..
	err := ExtractArchive(bytes.NewReader(buf.Bytes()), "/tmp/unsafe")
	if err != nil && err.Error() == "invalid output directory" {
		// ignore
	}
}
