package crypto

import (
	"os"
	"testing"
)

func TestTPMKeyStore_Logic(t *testing.T) {
	// Since we likely don't have a real TPM in the CI/environment,
	// we test the structure and error handling.
	// A mock would be better for full logic coverage if go-tpm supported it easily.

	baseDir, err := os.MkdirTemp("", "tpm-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baseDir)

	base := &FileSystemKeyStore{BaseDir: baseDir}
	tpmStore := NewTPMKeyStore(base, "/dev/null", []int{7, 14})

	if tpmStore.tpmPath != "/dev/null" {
		t.Errorf("expected /dev/null, got %s", tpmStore.tpmPath)
	}

	// Verify delegation
	if tpmStore.GetBaseDir() != baseDir {
		t.Errorf("GetBaseDir not delegated correctly")
	}

	// Test sealing with non-existent TPM should fail gracefully
	err = tpmStore.WriteKey("test.key", []byte("secret"), 0600)
	if err == nil {
		t.Error("expected error when writing to non-existent TPM device")
	}
}

func TestPCRSelectionMask(t *testing.T) {
	tests := []struct {
		pcrs     []int
		expected []byte
	}{
		{[]int{0}, []byte{0x01}},
		{[]int{7}, []byte{0x80}},
		{[]int{0, 7}, []byte{0x81}},
		{[]int{8}, []byte{0x00, 0x01}},
		{[]int{7, 14}, []byte{0x80, 0x40}},
	}

	for _, tc := range tests {
		s := &TPMKeyStore{pcrs: tc.pcrs}
		sel := s.makePCRSelection()
		mask := sel.PCRSelections[0].PCRSelect
		if string(mask) != string(tc.expected) {
			t.Errorf("for pcrs %v: expected %x, got %x", tc.pcrs, tc.expected, mask)
		}
	}
}
