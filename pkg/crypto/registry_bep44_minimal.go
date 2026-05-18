//go:build minimal

package crypto

import (
	"context"
	"fmt"
)

func init() {
	RegisterRegistry("bep44", func(conf *Config) IdentityRegistry {
		return &stubBEP44Registry{}
	})
}

// stubBEP44Registry satisfies the IdentityRegistry interface in minimal builds.
// BEP-44 DHT (anacrolix) is excluded from minimal builds to reduce binary size.
type stubBEP44Registry struct{}

func (s *stubBEP44Registry) Resolve(_ context.Context, _ string) (*IdentityRecord, error) {
	return nil, fmt.Errorf("BEP-44 registry not available in minimal build")
}

func (s *stubBEP44Registry) Publish(_ context.Context, _ *IdentityRecord) error {
	return fmt.Errorf("BEP-44 registry not available in minimal build")
}

func (s *stubBEP44Registry) Revoke(_ context.Context, _ string, _ []byte) error {
	return fmt.Errorf("BEP-44 registry not available in minimal build")
}

// NewBEP44Registry returns a stub in minimal builds.
func NewBEP44Registry(_ *Config) *stubBEP44Registry {
	return &stubBEP44Registry{}
}

func (s *stubBEP44Registry) PublishWithSIGKey(_ context.Context, _ *IdentityRecord, _ []byte) error {
	return fmt.Errorf("BEP-44 registry not available in minimal build")
}

// BEP44HandleFromSIGPub returns an error in minimal builds.
func BEP44HandleFromSIGPub(_ []byte) (string, error) {
	return "", fmt.Errorf("BEP-44 not available in minimal build")
}

// IsBEP44Handle returns false in minimal builds.
func IsBEP44Handle(_ string) bool { return false }
