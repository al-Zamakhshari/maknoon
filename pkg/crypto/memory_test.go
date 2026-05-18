package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"runtime"
	"testing"
)

// TestStreamingMemoryConstant verifies that the streaming encrypt pipeline uses
// bounded memory regardless of file size. HeapInuse delta for a 100MB encryption
// must be within 10× of the 1MB baseline — confirming O(chunk) not O(file) memory.
func TestStreamingMemoryConstant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory scaling test in short mode")
	}

	password := []byte("memory-const-test")

	heapDelta := func(size int) uint64 {
		data := make([]byte, size)
		if _, err := io.ReadFull(rand.Reader, data); err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)

		if err := EncryptStream(bytes.NewReader(data), io.Discard, password, FlagNone, 1, 0); err != nil {
			t.Fatalf("EncryptStream failed: %v", err)
		}

		runtime.GC()
		runtime.ReadMemStats(&after)
		if after.HeapInuse > before.HeapInuse {
			return after.HeapInuse - before.HeapInuse
		}
		return 0
	}

	delta1MB := heapDelta(1 * 1024 * 1024)
	delta100MB := heapDelta(100 * 1024 * 1024)

	t.Logf("HeapInuse delta — 1MB: %d bytes, 100MB: %d bytes", delta1MB, delta100MB)

	// Allow 10× headroom for GC non-determinism; constant-memory should be ~1×.
	// If delta100MB >> delta1MB by more than 10×, the pipeline isn't streaming.
	baseline := delta1MB + (2 * 1024 * 1024) // 1MB delta + 2MB floor
	if delta100MB > baseline*10 {
		t.Errorf("memory usage scales with file size (not constant): 1MB used %d bytes, 100MB used %d bytes",
			delta1MB, delta100MB)
	}
}
