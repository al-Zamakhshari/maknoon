package crypto

import (
	"bytes"
	"testing"
)

func engineForCrypto(t *testing.T) *Engine {
	t.Helper()
	return engineForVault(t) // same setup: temp HOME + HumanPolicy engine
}

// --- Protect / Unprotect via engine ---

func TestEngineCryptoProtectUnprotect(t *testing.T) {
	e := engineForCrypto(t)
	pass := []byte("engine-protect-pass")
	plain := []byte("engine protect round-trip test payload")

	var ct bytes.Buffer
	if _, err := e.Protect(nil, "test.bin", bytes.NewReader(plain), &ct, Options{Passphrase: pass}); err != nil {
		t.Fatalf("Protect: %v", err)
	}

	var out bytes.Buffer
	if _, err := e.Unprotect(nil, bytes.NewReader(ct.Bytes()), &out, "", Options{Passphrase: pass}); err != nil {
		t.Fatalf("Unprotect: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Error("Protect/Unprotect round-trip mismatch")
	}
}

func TestEngineCryptoProtectMultiRecipient(t *testing.T) {
	e := engineForCrypto(t)
	kemPub, kemPriv, _, _, _ := GeneratePQKeyPair(1)
	defer SafeClear(kemPriv)

	plain := []byte("multi-recipient engine protect")
	var ct bytes.Buffer
	if _, err := e.Protect(nil, "mr.bin", bytes.NewReader(plain), &ct, Options{Recipients: [][]byte{kemPub}}); err != nil {
		t.Fatalf("Protect multi-recipient: %v", err)
	}

	var out bytes.Buffer
	if _, err := e.Unprotect(nil, bytes.NewReader(ct.Bytes()), &out, "", Options{LocalPrivateKey: kemPriv}); err != nil {
		t.Fatalf("Unprotect multi-recipient: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Error("multi-recipient engine round-trip mismatch")
	}
}

// --- Sign / Verify via engine ---

func TestEngineCryptoSignVerify(t *testing.T) {
	e := engineForCrypto(t)
	_, _, sigPub, sigPriv, _ := GeneratePQKeyPair(1)
	defer SafeClear(sigPriv)

	data := []byte("engine sign/verify test")
	sig, err := e.Sign(nil, data, sigPriv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Error("Sign returned empty signature")
	}

	ok, err := e.Verify(nil, data, sig, sigPub)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("Verify failed for valid signature")
	}
}

func TestEngineCryptoVerifyTampered(t *testing.T) {
	e := engineForCrypto(t)
	_, _, sigPub, sigPriv, _ := GeneratePQKeyPair(1)
	defer SafeClear(sigPriv)

	data := []byte("tamper test")
	sig, _ := e.Sign(nil, data, sigPriv)

	// Corrupt the signature.
	sig[0] ^= 0xFF

	ok, _ := e.Verify(nil, data, sig, sigPub)
	if ok {
		t.Error("Verify should fail for tampered signature")
	}
}

// --- Wrap / Unwrap via engine ---

func TestEngineCryptoWrapUnwrap(t *testing.T) {
	e := engineForCrypto(t)
	kemPub, kemPriv, _, _, _ := GeneratePQKeyPair(1)
	defer SafeClear(kemPriv)

	dk, err := e.Wrap(nil, kemPub)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if len(dk.Plaintext) == 0 || len(dk.Wrapped) == 0 {
		t.Error("Wrap returned empty Plaintext or Wrapped key")
	}

	unwrapped, err := e.Unwrap(nil, dk.Wrapped, kemPriv)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(unwrapped, dk.Plaintext) {
		t.Error("Unwrap did not recover original plaintext key")
	}
}

// --- Inspect via engine ---

func TestEngineCryptoInspect(t *testing.T) {
	e := engineForCrypto(t)
	plain := []byte("inspect header test")
	pass := []byte("inspect-pass")

	var ct bytes.Buffer
	e.Protect(nil, "i.bin", bytes.NewReader(plain), &ct, Options{Passphrase: pass})

	info, err := e.Inspect(nil, bytes.NewReader(ct.Bytes()), false)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info == nil {
		t.Fatal("Inspect returned nil HeaderInfo")
	}
}

func TestEngineCryptoInspectAsymmetric(t *testing.T) {
	e := engineForCrypto(t)
	kemPub, _, _, _, _ := GeneratePQKeyPair(1)

	var ct bytes.Buffer
	e.Protect(nil, "asym.bin", bytes.NewReader([]byte("data")), &ct, Options{Recipients: [][]byte{kemPub}})

	info, err := e.Inspect(nil, bytes.NewReader(ct.Bytes()), false)
	if err != nil {
		t.Fatalf("Inspect asymmetric: %v", err)
	}
	if info == nil {
		t.Fatal("Inspect asymmetric returned nil")
	}
}

// --- Diagnostic ---

func TestEngineDiagnostic(t *testing.T) {
	e := engineForCrypto(t)
	d := e.Diagnostic()
	if d.System.Version == "" && d.Timestamp == "" {
		t.Error("Diagnostic returned empty result")
	}
}

// --- LoadCustomProfile via engine ---

func TestEngineLoadCustomProfile(t *testing.T) {
	e := engineForCrypto(t)
	_, err := e.LoadCustomProfile(nil, "/nonexistent/profile.json")
	if err == nil {
		t.Error("LoadCustomProfile should error for missing file")
	}
}
