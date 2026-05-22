package crypto

// Tests for encrypt/decrypt paths not covered by encrypt_test.go:
// - DecryptStreamWithPrivateKeyAndVerifier (legacy shim)
// - DecryptStreamWithPrivateKeyAndEvents (events context path)
// - EncryptStreamWithEvents (events context path)
// - EncryptStreamWithPublicKeysAndEvents (multi-recipient with context)
// - Multi-concurrency paths

import (
	"bytes"
	"context"
	"testing"
)

// DecryptStreamWithPrivateKeyAndVerifier is a legacy shim — just delegates.
func TestDecryptStreamWithPrivateKeyAndVerifier(t *testing.T) {
	kemPub, kemPriv, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}
	defer SafeClear(kemPriv)

	plaintext := []byte("legacy verifier shim test payload")
	var ct bytes.Buffer
	if err := EncryptStreamWithPublicKeys(bytes.NewReader(plaintext), &ct, [][]byte{kemPub}, FlagNone, 1, 0); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	var out bytes.Buffer
	_, _, err = DecryptStreamWithPrivateKeyAndVerifier(bytes.NewReader(ct.Bytes()), &out, kemPriv, nil, 1, false)
	if err != nil {
		t.Fatalf("DecryptStreamWithPrivateKeyAndVerifier: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Error("round-trip mismatch via legacy verifier shim")
	}
}

// EncryptStreamWithEvents uses the events context path.
func TestEncryptStreamWithEventsRoundTrip(t *testing.T) {
	pass := []byte("events-path-pass")
	plaintext := bytes.Repeat([]byte("events test "), 100)

	ectx := &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}

	var ct bytes.Buffer
	if err := encryptStreamSymV1(bytes.NewReader(plaintext), &ct, pass, FlagNone, 1, 0, ectx); err != nil {
		t.Fatalf("EncryptStreamWithEvents: %v", err)
	}

	var out bytes.Buffer
	if _, _, err := DecryptStreamWithEvents(bytes.NewReader(ct.Bytes()), &out, pass, 1, false, ectx); err != nil {
		t.Fatalf("DecryptStreamWithEvents: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Error("EncryptStreamWithEvents round-trip mismatch")
	}
}

func TestEncryptStreamWithEventsNilContext(t *testing.T) {
	// nil ectx should use default context.
	plaintext := []byte("nil context test")
	var ct bytes.Buffer
	if err := encryptStreamSymV1(bytes.NewReader(plaintext), &ct, []byte("pass"), FlagNone, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamWithEvents nil ctx: %v", err)
	}
	var out bytes.Buffer
	if _, _, err := DecryptStreamWithEvents(bytes.NewReader(ct.Bytes()), &out, []byte("pass"), 1, false, nil); err != nil {
		t.Fatalf("DecryptStreamWithEvents nil ctx: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Error("nil context round-trip mismatch")
	}
}

// DecryptStreamWithPrivateKeyAndEvents with explicit context.
func TestDecryptStreamWithPrivateKeyAndEvents(t *testing.T) {
	kemPub, kemPriv, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}
	defer SafeClear(kemPriv)

	plaintext := []byte("events decrypt path test")
	var ct bytes.Buffer
	if err := EncryptStreamWithPublicKeys(bytes.NewReader(plaintext), &ct, [][]byte{kemPub}, FlagNone, 1, 0); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	ectx := &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	var out bytes.Buffer
	_, _, err = DecryptStreamWithPrivateKeyAndEvents(bytes.NewReader(ct.Bytes()), &out, kemPriv, nil, 1, false, ectx)
	if err != nil {
		t.Fatalf("DecryptStreamWithPrivateKeyAndEvents: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Error("round-trip mismatch")
	}
}

func TestDecryptStreamWithPrivateKeyAndEventsNilWriter(t *testing.T) {
	// nil writer → io.Discard.
	kemPub, kemPriv, _, _, _ := GeneratePQKeyPair(1)
	defer SafeClear(kemPriv)

	var ct bytes.Buffer
	EncryptStreamWithPublicKeys(bytes.NewReader([]byte("discard")), &ct, [][]byte{kemPub}, FlagNone, 1, 0)
	_, _, err := DecryptStreamWithPrivateKeyAndEvents(bytes.NewReader(ct.Bytes()), nil, kemPriv, nil, 1, false, nil)
	if err != nil {
		t.Fatalf("nil writer should use Discard: %v", err)
	}
}

// Multi-recipient: encrypt to 3 recipients, each can decrypt independently.
func TestEncryptStreamWithPublicKeysAndEventsMultiRecipient(t *testing.T) {
	const n = 3
	privKeys := make([][]byte, n)
	pubKeys := make([][]byte, n)
	for i := 0; i < n; i++ {
		pub, priv, _, _, err := GeneratePQKeyPair(1)
		if err != nil {
			t.Fatalf("GeneratePQKeyPair[%d]: %v", i, err)
		}
		privKeys[i] = priv
		pubKeys[i] = pub
	}
	defer func() {
		for _, k := range privKeys {
			SafeClear(k)
		}
	}()

	plaintext := []byte("multi-recipient message for three parties")
	ectx := &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}

	var ct bytes.Buffer
	if err := encryptStreamAsymV1(bytes.NewReader(plaintext), &ct, pubKeys, nil, FlagNone, 1, 1, ectx); err != nil {
		t.Fatalf("EncryptStreamWithPublicKeysAndEvents: %v", err)
	}

	// Every recipient must decrypt successfully.
	for i, priv := range privKeys {
		var out bytes.Buffer
		_, _, err := DecryptStreamWithPrivateKeyAndEvents(bytes.NewReader(ct.Bytes()), &out, priv, nil, 1, false, ectx)
		if err != nil {
			t.Errorf("recipient %d decrypt failed: %v", i, err)
			continue
		}
		if !bytes.Equal(out.Bytes(), plaintext) {
			t.Errorf("recipient %d plaintext mismatch", i)
		}
	}
}

// Parallel concurrency path (concurrency > 1).
func TestEncryptDecryptParallelConcurrency(t *testing.T) {
	// Data large enough that parallel workers actually fire.
	plaintext := bytes.Repeat([]byte("parallel concurrency test block "), 1024) // ~32 KB
	pass := []byte("parallel-pass")

	var ct bytes.Buffer
	if err := encryptStreamSymV1(bytes.NewReader(plaintext), &ct, pass, FlagNone, 4, 0, nil); err != nil {
		t.Fatalf("encrypt concurrent: %v", err)
	}

	var out bytes.Buffer
	if _, _, err := DecryptStreamWithEvents(bytes.NewReader(ct.Bytes()), &out, pass, 4, false, nil); err != nil {
		t.Fatalf("decrypt concurrent: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Error("parallel concurrency round-trip mismatch")
	}
}

// EncryptStreamNoHeader + DecryptStreamWithEvents (stealth=true).
func TestEncryptStreamNoHeaderRoundTrip(t *testing.T) {
	pass := []byte("no-header-pass")
	plaintext := []byte("stealth no-header payload")

	var ct bytes.Buffer
	if err := EncryptStreamNoHeader(bytes.NewReader(plaintext), &ct, pass, FlagNone, 1, 1, nil); err != nil {
		t.Fatalf("EncryptStreamNoHeader: %v", err)
	}

	var out bytes.Buffer
	if _, _, err := DecryptStreamWithEvents(bytes.NewReader(ct.Bytes()), &out, pass, 1, true, nil); err != nil {
		t.Fatalf("decrypt stealth: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Error("no-header round-trip mismatch")
	}
}
