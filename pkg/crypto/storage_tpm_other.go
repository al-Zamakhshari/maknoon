//go:build !linux
// +build !linux

package crypto

import (
	"fmt"
)

func defaultTPMPath() string {
	return ""
}

func (s *TPMKeyStore) seal(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("TPM-backed storage is currently only supported on Linux")
}

func (s *TPMKeyStore) unseal(blob []byte) ([]byte, error) {
	return nil, fmt.Errorf("TPM-backed storage is currently only supported on Linux")
}
