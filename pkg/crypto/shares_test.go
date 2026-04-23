package crypto

import (
	"bytes"
	"testing"
)

func TestSSS(t *testing.T) {
	secret := []byte("this is a very secret message")
	m, n := 3, 5

	shares, err := SplitSecret(secret, m, n)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}

	if len(shares) != n {
		t.Errorf("expected %d shares, got %d", n, len(shares))
	}

	// Try combining with threshold
	thresholdShares := shares[:m]
	recovered, err := CombineShares(thresholdShares)
	if err != nil {
		t.Fatalf("CombineShares failed: %v", err)
	}

	if !bytes.Equal(secret, recovered) {
		t.Errorf("recovered secret mismatch: expected %s, got %s", string(secret), string(recovered))
	}

	// Try combining with all shares
	recoveredAll, err := CombineShares(shares)
	if err != nil {
		t.Fatalf("CombineShares (all) failed: %v", err)
	}
	if !bytes.Equal(secret, recoveredAll) {
		t.Errorf("recovered secret (all) mismatch")
	}

	// Try combining with insufficient shares
	_, err = CombineShares(shares[:m-1])
	if err == nil {
		t.Errorf("expected error for insufficient shares, got nil")
	}
}

func TestMnemonic(t *testing.T) {
	secret := []byte("pqc-key-material")
	m, n := 2, 3
	shares, _ := SplitSecret(secret, m, n)

	share := shares[0]
	mnemonic := share.ToMnemonic()
	t.Logf("Mnemonic: %s", mnemonic)

	restored, err := FromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic failed: %v", err)
	}

	if share.Version != restored.Version || share.Threshold != restored.Threshold || share.Index != restored.Index {
		t.Errorf("restored share header mismatch")
	}
	if !bytes.Equal(share.Data, restored.Data) {
		t.Errorf("restored share data mismatch")
	}
	if !bytes.Equal(share.Checksum, restored.Checksum) {
		t.Errorf("restored share checksum mismatch")
	}
}

func TestCombineDuplicateShares(t *testing.T) {
	secret := []byte("panic-prevention-test")
	m, n := 2, 3
	shares, _ := SplitSecret(secret, m, n)

	// Attempt to combine with duplicate shares
	badShares := []Share{shares[0], shares[0]}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("CombineShares panicked with duplicate shares: %v", r)
		}
	}()

	_, err := CombineShares(badShares)
	if err == nil {
		t.Errorf("expected error for duplicate shares, got nil")
	}
	if err != nil && !bytes.Contains([]byte(err.Error()), []byte("duplicate share")) {
		t.Errorf("expected duplicate share error, got: %v", err)
	}
}
