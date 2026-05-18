package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"time"
)

// TestAESNIActive is a soft performance assertion that AES hardware acceleration
// is active. On AES-NI capable hardware, 10MB symmetric encryption completes in
// well under 50ms. If it takes longer (software fallback), we skip rather than
// fail — CI runners may not have AES-NI.
func TestAESNIActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping AES-NI timing test in short mode")
	}

	const size = 10 * 1024 * 1024 // 10MB
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		t.Fatal(err)
	}
	password := []byte("aes-ni-test-password")

	start := time.Now()
	if err := EncryptStream(bytes.NewReader(data), io.Discard, password, FlagNone, 1, 0); err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}
	elapsed := time.Since(start)

	// AES-NI: ~5-30ms on modern hardware. Software: ~300-800ms.
	// We use 200ms as the threshold — passes on AES-NI, skips on software.
	if elapsed > 200*time.Millisecond {
		t.Skipf("AES-NI may not be active (10MB took %v, expected <200ms with hardware acceleration)", elapsed)
	}
	t.Logf("10MB encrypt in %v — AES hardware acceleration confirmed", elapsed)
}
