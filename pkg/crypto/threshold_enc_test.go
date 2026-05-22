package crypto

import (
	"bytes"
	"os"
	"testing"
)

func TestThresholdEncryptDecrypt2of3(t *testing.T) {
	// Generate 3 recipient keypairs.
	kemPubs := make([][]byte, 3)
	kemPrivs := make([][]byte, 3)
	for i := range kemPubs {
		pub, priv, _, _, err := GeneratePQKeyPair(1)
		if err != nil {
			t.Fatalf("GeneratePQKeyPair[%d]: %v", i, err)
		}
		kemPubs[i] = pub
		kemPrivs[i] = priv
		defer SafeClear(kemPrivs[i])
	}

	plain := []byte("threshold decryption test payload — 2-of-3")

	// Encrypt with threshold 2.
	var ct bytes.Buffer
	if err := EncryptStreamThreshold(bytes.NewReader(plain), &ct, kemPubs, 2, FlagNone, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamThreshold: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatal("ciphertext is empty")
	}

	// Collect share from recipient 0.
	share0, err := DecryptThresholdCollectShare(bytes.NewReader(ct.Bytes()), kemPrivs[0], 0)
	if err != nil {
		t.Fatalf("CollectShare[0]: %v", err)
	}
	if share0.Threshold != 2 {
		t.Errorf("share0.Threshold = %d, want 2", share0.Threshold)
	}

	// Collect share from recipient 1.
	share1, err := DecryptThresholdCollectShare(bytes.NewReader(ct.Bytes()), kemPrivs[1], 0)
	if err != nil {
		t.Fatalf("CollectShare[1]: %v", err)
	}

	// Combine 2 shares — should decrypt successfully.
	var out bytes.Buffer
	if err := DecryptThresholdCombine(bytes.NewReader(ct.Bytes()), &out, "", []*ThresholdShare{share0, share1}, nil); err != nil {
		t.Fatalf("DecryptThresholdCombine: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Errorf("plaintext mismatch\ngot:  %q\nwant: %q", out.Bytes(), plain)
	}
}

func TestThresholdInsufficientShares(t *testing.T) {
	kemPubs := make([][]byte, 3)
	kemPrivs := make([][]byte, 3)
	for i := range kemPubs {
		pub, priv, _, _, err := GeneratePQKeyPair(1)
		if err != nil {
			t.Fatalf("GeneratePQKeyPair[%d]: %v", i, err)
		}
		kemPubs[i] = pub
		kemPrivs[i] = priv
		defer SafeClear(kemPrivs[i])
	}

	var ct bytes.Buffer
	EncryptStreamThreshold(bytes.NewReader([]byte("secret")), &ct, kemPubs, 2, FlagNone, 1, 0, nil)

	// Only one share — should fail.
	share0, _ := DecryptThresholdCollectShare(bytes.NewReader(ct.Bytes()), kemPrivs[0], 0)
	var out bytes.Buffer
	err := DecryptThresholdCombine(bytes.NewReader(ct.Bytes()), &out, "", []*ThresholdShare{share0}, nil)
	if err == nil {
		t.Error("expected error with insufficient shares, got nil")
	}
}

func TestThresholdShareJSONRoundtrip(t *testing.T) {
	original := &ThresholdShare{
		Version:   1,
		Threshold: 3,
		Total:     5,
		Index:     2,
		ShareData: []byte{0x01, 0x02, 0x03, 0xde, 0xad, 0xbe, 0xef},
	}
	data, err := ThresholdShareToJSON(original)
	if err != nil {
		t.Fatalf("ThresholdShareToJSON: %v", err)
	}
	recovered, err := ThresholdShareFromJSON(data)
	if err != nil {
		t.Fatalf("ThresholdShareFromJSON: %v", err)
	}
	if recovered.Index != original.Index || recovered.Threshold != original.Threshold {
		t.Errorf("JSON roundtrip mismatch: got %+v, want %+v", recovered, original)
	}
	if !bytes.Equal(recovered.ShareData, original.ShareData) {
		t.Error("ShareData mismatch after JSON roundtrip")
	}
}

func TestThresholdShareToFile(t *testing.T) {
	pub, priv, _, _, _ := GeneratePQKeyPair(1)
	defer SafeClear(priv)

	var ct bytes.Buffer
	EncryptStreamThreshold(bytes.NewReader([]byte("file test")), &ct, [][]byte{pub, pub}, 2, FlagNone, 1, 0, nil)

	share, _ := DecryptThresholdCollectShare(bytes.NewReader(ct.Bytes()), priv, 0)
	shareJSON, _ := ThresholdShareToJSON(share)

	f := t.TempDir() + "/share.json"
	os.WriteFile(f, shareJSON, 0600)
	data, _ := os.ReadFile(f)
	recovered, err := ThresholdShareFromJSON(data)
	if err != nil {
		t.Fatalf("recover from file: %v", err)
	}
	if recovered.Index != share.Index {
		t.Errorf("index mismatch: got %d, want %d", recovered.Index, share.Index)
	}
}
