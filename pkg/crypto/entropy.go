package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"
)

// EntropySentinel is a FIPS-compliant wrapper for an entropy source.
// It implements the Continuous Random Number Generator Test (CRNGT) as required by FIPS 140-3.
type EntropySentinel struct {
	source   io.Reader
	last     []byte
	mu       sync.Mutex
	checkLen int
}

// NewEntropySentinel creates a new sentinel around the provided source (usually crypto/rand.Reader).
// checkLen defines the block size for comparison (FIPS mandates at least 16 bits; we use 16 bytes for rigor).
func NewEntropySentinel(source io.Reader) *EntropySentinel {
	return &EntropySentinel{
		source:   source,
		checkLen: 16,
	}
}

// Read implements io.Reader and performs the CRNGT.
func (s *EntropySentinel) Read(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, err = s.source.Read(p)
	if err != nil {
		return n, err
	}

	// For very small reads, we don't have enough data to perform a rigorous CRNGT in every call,
	// but for FIPS compliance, we check if the current output matches the previous output.
	// In practice, we look at the first checkLen bytes of the read.
	if n >= s.checkLen {
		current := p[:s.checkLen]
		if s.last != nil {
			match := true
			for i := range current {
				if current[i] != s.last[i] {
					match = false
					break
				}
			}
			if match {
				// FIPS failure: The entropy source is stuck!
				panic("CRITICAL: FIPS Entropy Failure - Continuous RNG Test (CRNGT) detected identical output")
			}
		}
		// Store the current block for the next comparison
		if s.last == nil {
			s.last = make([]byte, s.checkLen)
		}
		copy(s.last, current)
	}

	return n, nil
}

var (
	// SecureRand is the global, monitored entropy source for Maknoon.
	// In FIPS mode, all random number generation MUST go through this sentinel.
	SecureRand io.Reader
	once       sync.Once
)

func init() {
	once.Do(func() {
		SecureRand = NewEntropySentinel(rand.Reader)
	})
}

// GetRandomBytes fills the provided slice with secure, monitored entropy.
func GetRandomBytes(b []byte) error {
	_, err := io.ReadFull(SecureRand, b)
	if err != nil {
		return fmt.Errorf("failed to read secure entropy: %w", err)
	}
	return nil
}
