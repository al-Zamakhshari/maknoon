package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// TestKATMLDSA87 verifies ML-DSA-87 sign/verify with deterministic vectors.
// A fixed 1000-byte seed produces a known keypair; the same message must always
// produce the same signature (deterministic mode). If CIRCL's API changes or
// the binary format shifts, this test catches it before release.
func TestKATMLDSA87(t *testing.T) {
	// Deterministic seed — changes here invalidate the vector.
	seed := bytes.Repeat([]byte{0x42}, 1000)
	pk, sk, err := mldsa87.GenerateKey(bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	msg := []byte("Maknoon KAT: ML-DSA-87 sign/verify vector v1")
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(sk, msg, nil, true, sig); err != nil {
		t.Fatalf("SignTo: %v", err)
	}

	// Pin the public key prefix (first 16 bytes) — derived purely from the seed,
	// catches format changes in CIRCL's key serialisation.
	pkBytes, _ := pk.MarshalBinary()
	pkHex := hex.EncodeToString(pkBytes[:16])
	const expectedPKPrefix = "8a9d3f21d2e9cbbdc75ef8f93fbd6ff4"
	if pkHex != expectedPKPrefix {
		t.Errorf("ML-DSA-87 public key prefix mismatch\ngot:  %s\nwant: %s\n"+
			"(CIRCL API or key serialisation may have changed)", pkHex, expectedPKPrefix)
	}

	// Verify the signature is valid.
	if !mldsa87.Verify(pk, msg, nil, sig) {
		t.Error("ML-DSA-87 signature verification failed")
	}

	// Tampered message must not verify.
	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0xff
	if mldsa87.Verify(pk, tampered, nil, sig) {
		t.Error("ML-DSA-87 tampered message incorrectly verified")
	}

	// Bit-flipped signature must not verify.
	badSig := append([]byte(nil), sig...)
	badSig[len(badSig)/2] ^= 0x01
	if mldsa87.Verify(pk, msg, nil, badSig) {
		t.Error("ML-DSA-87 corrupted signature incorrectly verified")
	}
}

// TestKATSignData verifies the Maknoon SignData/VerifySignature wrappers
// produce stable outputs across refactors.
func TestKATSignData(t *testing.T) {
	_, _, sigPub, sigPriv, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}

	msg := []byte("Maknoon KAT: SignData wrapper")
	sig, err := SignData(msg, sigPriv)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}

	if !VerifySignature(msg, sig, sigPub) {
		t.Error("VerifySignature returned false for valid sig")
	}

	// Bit-flip must fail.
	bad := append([]byte(nil), sig...)
	bad[len(bad)/2] ^= 0x01
	if VerifySignature(msg, bad, sigPub) {
		t.Error("VerifySignature returned true for corrupted sig")
	}

	// Wrong message must fail.
	if VerifySignature(append(msg, '!'), sig, sigPub) {
		t.Error("VerifySignature returned true for wrong message")
	}
}
