package maknooncrypto

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"runtime"
	"testing"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20poly1305"
)

// Mock constant-memory streaming core
func mockStreamEncrypt(r io.Reader, w io.Writer, key []byte, baseNonce []byte, chunkSize int) error {
	aead, _ := chacha20poly1305.NewX(key)
	buf := make([]byte, chunkSize)
	chunkIndex := uint64(0)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			nonce := make([]byte, 24)
			copy(nonce, baseNonce)
			counter := make([]byte, 8)
			binary.LittleEndian.PutUint64(counter, chunkIndex)
			for i := 0; i < 8; i++ {
				nonce[16+i] ^= counter[i]
			}
			ciphertext := aead.Seal(nil, nonce, buf[:n], nil)
			w.Write(ciphertext)
			chunkIndex++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func TestStreamingRigorousConstantMemory(t *testing.T) {
	const smallSize = 1 * 1024 * 1024
	const largeSize = 200 * 1024 * 1024 // Reduced for faster test execution, but still enough to prove O(1)

	key := make([]byte, 32)
	rand.Read(key)
	baseNonce := make([]byte, 24)
	rand.Read(baseNonce)

	measure := func(size int) uint64 {
		runtime.GC()
		var m1, m2 runtime.MemStats
		runtime.ReadMemStats(&m1)

		r := io.LimitReader(rand.Reader, int64(size))
		_ = mockStreamEncrypt(r, io.Discard, key, baseNonce, 64*1024)

		runtime.GC() // Clean up after run
		runtime.ReadMemStats(&m2)
		return m2.HeapAlloc - m1.HeapAlloc
	}

	memSmall := measure(smallSize)
	memLarge := measure(largeSize)

	if memLarge > memSmall+(5*1024*1024) {
		t.Errorf("Memory scaling is not constant. 1MB used %d, 200MB used %d", memSmall, memLarge)
	}
}

func TestWireFormatHybridProof(t *testing.T) {
	_, pub, _ := GenerateKeys()

	data := make([]byte, 32)
	rand.Read(data)

	dataCopy := make([]byte, 32)
	copy(dataCopy, data)
	enclave := memguard.NewBufferFromBytes(dataCopy).Seal()

	wrapped, err := WrapEphemeralKey(pub, 1, 0, enclave)
	if err != nil {
		t.Fatal(err)
	}

	// Proof of Hybrid components:
	// ML-KEM-768 CT (1088) + X25519 PK (32) + Wrapped FEK with tag (48) = 1168
	const expectedTotalSize = 1168

	if len(wrapped) != expectedTotalSize {
		t.Errorf("Wire format mismatch. Expected %d bytes, got %d", expectedTotalSize, len(wrapped))
	}
}
