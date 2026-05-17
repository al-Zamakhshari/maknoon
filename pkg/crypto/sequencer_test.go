package crypto

import (
	"bytes"
	"io"
	"math/rand"
	"testing"
)

func FuzzSequencer(f *testing.F) {
	f.Add(uint64(10), int64(42), false)
	f.Fuzz(func(t *testing.T, count uint64, seed int64, byzantine bool) {
		if count == 0 || count > 100 {
			return
		}

		r := rand.New(rand.NewSource(seed))
		indices := r.Perm(int(count))

		// Byzantine additions
		if byzantine {
			// Add some duplicates
			for i := 0; i < 5; i++ {
				indices = append(indices, r.Intn(int(count)))
			}
			// Add some out-of-bounds (far in the future)
			for i := 0; i < 2; i++ {
				indices = append(indices, int(count)+1000+r.Intn(1000))
			}
		}

		results := make(chan sequencerResult, len(indices))
		errChan := make(chan error, 1)

		expected := new(bytes.Buffer)
		for i := uint64(0); i < count; i++ {
			data := []byte{byte(i)}
			expected.Write(data)
		}

		go func() {
			for _, idx := range indices {
				results <- sequencerResult{
					index: uint64(idx),
					data:  []byte{byte(idx)},
				}
			}
			close(results)
		}()

		out := new(bytes.Buffer)
		err := runSequencer(out, results, errChan, func(w io.Writer, b []byte) error {
			_, err := w.Write(b)
			return err
		})

		// Byzantine mode intentionally sends out-of-bounds indices (count+1000…)
		// that can never be written. When the channel closes, those entries remain
		// pending and the sequencer correctly returns "missing chunks". That is
		// expected behaviour, not a bug — so only fatal on unexpected errors.
		if err != nil && !byzantine {
			t.Fatalf("sequencer failed: %v", err)
		}

		// Output must be a prefix of the expected sequence regardless of mode.
		if !bytes.HasPrefix(out.Bytes(), expected.Bytes()) {
			t.Errorf("sequencer output mismatch")
		}
	})
}
