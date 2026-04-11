package crypto

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
)

func TestParallelEquivalence(t *testing.T) {
	password := []byte("parallel-test-password")
	// 1MB to ensure many chunks
	originalData := make([]byte, 1024*1024)
	if _, err := io.ReadFull(rand.Reader, originalData); err != nil {
		t.Fatal(err)
	}

	// 1. Encrypt Parallel (concurrency = 0 -> auto)
	var encryptedPar bytes.Buffer
	if err := EncryptStream(bytes.NewReader(originalData), &encryptedPar, password, FlagNone, 0); err != nil {
		t.Fatalf("Parallel encryption failed: %v", err)
	}

	// 2. Decrypt Sequential (concurrency = 1)
	var decryptedSeq bytes.Buffer
	if _, err := DecryptStream(bytes.NewReader(encryptedPar.Bytes()), &decryptedSeq, password, 1); err != nil {
		t.Fatalf("Sequential decryption of parallel-encrypted data failed: %v", err)
	}

	// 3. Verify Sequential Decryption
	if !bytes.Equal(originalData, decryptedSeq.Bytes()) {
		t.Fatal("Decrypted data (sequential) does not match original data")
	}

	// 4. Decrypt Parallel (concurrency = 0 -> auto)
	var decryptedPar bytes.Buffer
	if _, err := DecryptStream(bytes.NewReader(encryptedPar.Bytes()), &decryptedPar, password, 0); err != nil {
		t.Fatalf("Parallel decryption failed: %v", err)
	}

	// 5. Verify Parallel Decryption
	if !bytes.Equal(originalData, decryptedPar.Bytes()) {
		t.Fatal("Decrypted data (parallel) does not match original data")
	}
}

func TestResequencingChaos(t *testing.T) {
	// This test focuses on the resequencer's ability to handle out-of-order chunks.
	// Since we can't easily force the worker pool to be out-of-order without mocks,
	// we will rely on the fact that with high concurrency and many small chunks,
	// natural scheduling will likely cause some reordering.

	password := []byte("chaos-password")
	chunkCount := 100
	dataSize := chunkCount * ChunkSize
	originalData := make([]byte, dataSize)
	rand.Read(originalData)

	// Use a high concurrency to increase the chance of out-of-order execution
	concurrency := 16

	var encrypted bytes.Buffer
	if err := EncryptStream(bytes.NewReader(originalData), &encrypted, password, FlagNone, concurrency); err != nil {
		t.Fatal(err)
	}

	var decrypted bytes.Buffer
	if _, err := DecryptStream(bytes.NewReader(encrypted.Bytes()), &decrypted, password, concurrency); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(originalData, decrypted.Bytes()) {
		t.Fatal("Chaos test failed: data corruption during parallel processing")
	}
}

func TestConcurrencyEdgeCases(t *testing.T) {
	password := []byte("edge-case")
	data := []byte("minimal data")

	tests := []struct {
		name        string
		concurrency int
	}{
		{"Concurrency 1", 1},
		{"Concurrency 2", 2},
		{"Concurrency 100", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var enc, dec bytes.Buffer
			if err := EncryptStream(bytes.NewReader(data), &enc, password, FlagNone, tt.concurrency); err != nil {
				t.Fatal(err)
			}
			if _, err := DecryptStream(bytes.NewReader(enc.Bytes()), &dec, password, tt.concurrency); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, dec.Bytes()) {
				t.Errorf("Round-trip failed for concurrency %d", tt.concurrency)
			}
		})
	}
}

func BenchmarkEncryption(b *testing.B) {
	password := []byte("bench")
	dataSize := 10 * 1024 * 1024 // 10MB
	data := make([]byte, dataSize)
	rand.Read(data)

	concurrencies := []int{1, 2, 4, 8}

	for _, c := range concurrencies {
		b.Run(fmt.Sprintf("Concurrency-%d", c), func(b *testing.B) {
			b.SetBytes(int64(dataSize))
			for i := 0; i < b.N; i++ {
				var out bytes.Buffer
				EncryptStream(bytes.NewReader(data), &out, password, FlagNone, c)
			}
		})
	}
}
