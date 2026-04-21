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
	if err := EncryptStream(bytes.NewReader(originalData), &encryptedPar, password, FlagNone, 0, 0); err != nil {
		t.Fatalf("Parallel encryption failed: %v", err)
	}

	// 2. Decrypt Sequential (concurrency = 1)
	var decryptedSeq bytes.Buffer
	if _, _, err := DecryptStream(bytes.NewReader(encryptedPar.Bytes()), &decryptedSeq, password, 1, false); err != nil {
		t.Fatalf("Sequential decryption of parallel-encrypted data failed: %v", err)
	}

	// 3. Verify Sequential Decryption
	if !bytes.Equal(originalData, decryptedSeq.Bytes()) {
		t.Fatal("Decrypted data (sequential) does not match original data")
	}

	// 4. Decrypt Parallel (concurrency = 0 -> auto)
	var decryptedPar bytes.Buffer
	if _, _, err := DecryptStream(bytes.NewReader(encryptedPar.Bytes()), &decryptedPar, password, 0, false); err != nil {
		t.Fatalf("Parallel decryption failed: %v", err)
	}

	// 5. Verify Parallel Decryption
	if !bytes.Equal(originalData, decryptedPar.Bytes()) {
		t.Fatal("Decrypted data (parallel) does not match original data")
	}
}

func TestResequencingChaos(t *testing.T) {
	password := []byte("chaos-password")
	chunkCount := 100
	dataSize := chunkCount * ChunkSize
	originalData := make([]byte, dataSize)
	_, _ = rand.Read(originalData)

	concurrency := 16

	var encrypted bytes.Buffer
	if err := EncryptStream(bytes.NewReader(originalData), &encrypted, password, FlagNone, concurrency, 0); err != nil {
		t.Fatal(err)
	}

	var decrypted bytes.Buffer
	if _, _, err := DecryptStream(bytes.NewReader(encrypted.Bytes()), &decrypted, password, concurrency, false); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(originalData, decrypted.Bytes()) {
		t.Fatal("Chaos test failed: data corruption during parallel processing")
	}
}

func BenchmarkEncryption(b *testing.B) {
	password := []byte("bench")
	dataSize := 10 * 1024 * 1024 // 10MB
	data := make([]byte, dataSize)
	_, _ = rand.Read(data)

	concurrencies := []int{1, 2, 4, 8}

	for _, c := range concurrencies {
		b.Run(fmt.Sprintf("Encrypt-Concurrency-%d", c), func(b *testing.B) {
			b.SetBytes(int64(dataSize))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := EncryptStream(bytes.NewReader(data), io.Discard, password, FlagNone, c, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecryption(b *testing.B) {
	password := []byte("bench")
	dataSize := 10 * 1024 * 1024 // 10MB
	data := make([]byte, dataSize)
	_, _ = rand.Read(data)

	var encrypted bytes.Buffer
	if err := EncryptStream(bytes.NewReader(data), &encrypted, password, FlagNone, 0, 0); err != nil {
		b.Fatal(err)
	}
	encData := encrypted.Bytes()

	concurrencies := []int{1, 2, 4, 8}

	for _, c := range concurrencies {
		b.Run(fmt.Sprintf("Decrypt-Concurrency-%d", c), func(b *testing.B) {
			b.SetBytes(int64(dataSize))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := DecryptStream(bytes.NewReader(encData), io.Discard, password, c, false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// faultyReader simulates a stream that breaks unexpectedly (e.g. network drop)
type faultyReader struct {
	data      []byte
	readCount int
	failAfter int
}

func (f *faultyReader) Read(p []byte) (n int, err error) {
	if f.readCount >= f.failAfter {
		return 0, fmt.Errorf("simulated stream failure")
	}
	n = copy(p, f.data[f.readCount:])
	f.readCount += n
	return n, nil
}

func TestPipelineCancellation(t *testing.T) {
	password := []byte("cancellation-test")

	// Create 5MB of data
	originalData := make([]byte, 5*1024*1024)
	_, _ = rand.Read(originalData)

	// Fail after reading exactly 2MB (forcing failure mid-stream)
	reader := &faultyReader{
		data:      originalData,
		failAfter: 2 * 1024 * 1024,
	}

	var encrypted bytes.Buffer

	// Use high concurrency to maximize the chance of race conditions during teardown
	err := EncryptStream(reader, &encrypted, password, FlagNone, 16, 0)

	if err == nil {
		t.Fatal("Expected encryption to fail due to simulated stream interruption")
	}
	if err.Error() != "simulated stream failure" {
		t.Fatalf("Expected 'simulated stream failure', got: %v", err)
	}
}
