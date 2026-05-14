package crypto

import (
	"fmt"
	"github.com/google/go-tpm/tpm2"
)

// TPMKeyStore is a hardware-hardened KeyStore that uses a TPM 2.0 device
// to protect sensitive cryptographic material.
type TPMKeyStore struct {
	base    KeyStore
	tpmPath string
	pcrs    []int
}

// NewTPMKeyStore creates a new TPM-backed KeyStore.
func NewTPMKeyStore(base KeyStore, tpmPath string, pcrs []int) *TPMKeyStore {
	if tpmPath == "" {
		tpmPath = defaultTPMPath()
	}
	return &TPMKeyStore{
		base:    base,
		tpmPath: tpmPath,
		pcrs:    pcrs,
	}
}

func (s *TPMKeyStore) ReadKey(path string) ([]byte, error) {
	data, err := s.base.ReadKey(path)
	if err != nil {
		return nil, err
	}

	// For Phase 8, we attempt to unseal if the data looks like a TPM blob.
	unwrapped, err := s.unseal(data)
	if err != nil {
		// Fallback to raw read for non-wrapped keys (migration support)
		return data, nil
	}
	return unwrapped, nil
}

func (s *TPMKeyStore) WriteKey(path string, data []byte, perm uint32) error {
	wrapped, err := s.seal(data)
	if err != nil {
		return fmt.Errorf("TPM seal failed: %w", err)
	}
	return s.base.WriteKey(path, wrapped, perm)
}

func (s *TPMKeyStore) Exists(path string) bool               { return s.base.Exists(path) }
func (s *TPMKeyStore) ListKeys(dir string) ([]string, error) { return s.base.ListKeys(dir) }
func (s *TPMKeyStore) EnsureDir(dir string) error            { return s.base.EnsureDir(dir) }
func (s *TPMKeyStore) ResolvePath(name string) (string, error) {
	return s.base.ResolvePath(name)
}
func (s *TPMKeyStore) GetBaseDir() string { return s.base.GetBaseDir() }

func (s *TPMKeyStore) makePCRSelection() tpm2.TPMLPCRSelection {
	max := 0
	for _, p := range s.pcrs {
		if p > max {
			max = p
		}
	}
	mask := make([]byte, (max/8)+1)
	for _, p := range s.pcrs {
		mask[p/8] |= 1 << (uint(p) % 8)
	}
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: mask,
			},
		},
	}
}
