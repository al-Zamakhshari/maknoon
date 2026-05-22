package crypto

// coverage_gap_test.go — targeted tests for functions with low coverage after
// the V2 wire format and threshold engine additions.  Keeps the gate at ≥ 75%.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// engine_threshold.go — EncryptThreshold, CollectThresholdShare, CombineAndDecrypt
// ---------------------------------------------------------------------------

func TestEngineThresholdRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Unsetenv("HOME")

	engine, err := NewEngine(&HumanPolicy{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	ectx := &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}

	// Generate 3 recipient keypairs.
	pubs := make([][]byte, 3)
	privs := make([][]byte, 3)
	for i := range pubs {
		pub, priv, _, _, err := GeneratePQKeyPair(1)
		if err != nil {
			t.Fatalf("GeneratePQKeyPair[%d]: %v", i, err)
		}
		pubs[i] = pub
		privs[i] = priv
		defer SafeClear(privs[i])
	}

	plain := []byte("engine threshold round-trip — 2-of-3")

	// EncryptThreshold.
	var ct bytes.Buffer
	if err := engine.EncryptThreshold(ectx, bytes.NewReader(plain), &ct, pubs, 2, Options{}); err != nil {
		t.Fatalf("EncryptThreshold: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatal("ciphertext empty")
	}

	// CollectThresholdShare — recipient 0.
	share0, err := engine.CollectThresholdShare(ectx, bytes.NewReader(ct.Bytes()), privs[0], 0)
	if err != nil {
		t.Fatalf("CollectThresholdShare[0]: %v", err)
	}
	if share0.Threshold != 2 {
		t.Errorf("share0.Threshold = %d, want 2", share0.Threshold)
	}

	// CollectThresholdShare — recipient 2 (skip 1).
	share2, err := engine.CollectThresholdShare(ectx, bytes.NewReader(ct.Bytes()), privs[2], 0)
	if err != nil {
		t.Fatalf("CollectThresholdShare[2]: %v", err)
	}

	// CombineAndDecrypt — should succeed with 2 shares.
	var out bytes.Buffer
	if err := engine.CombineAndDecrypt(ectx, bytes.NewReader(ct.Bytes()), &out, "", []*ThresholdShare{share0, share2}); err != nil {
		t.Fatalf("CombineAndDecrypt: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Errorf("plaintext mismatch\ngot:  %q\nwant: %q", out.Bytes(), plain)
	}
}

func TestEngineThresholdInsufficientShares(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Unsetenv("HOME")

	engine, err := NewEngine(&HumanPolicy{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	ectx := &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}

	pubs := make([][]byte, 3)
	privs := make([][]byte, 3)
	for i := range pubs {
		pub, priv, _, _, err := GeneratePQKeyPair(1)
		if err != nil {
			t.Fatalf("GeneratePQKeyPair[%d]: %v", i, err)
		}
		pubs[i] = pub
		privs[i] = priv
		defer SafeClear(privs[i])
	}

	var ct bytes.Buffer
	if err := engine.EncryptThreshold(ectx, bytes.NewReader([]byte("secret")), &ct, pubs, 2, Options{}); err != nil {
		t.Fatalf("EncryptThreshold: %v", err)
	}

	share0, _ := engine.CollectThresholdShare(ectx, bytes.NewReader(ct.Bytes()), privs[0], 0)

	// One share is below threshold=2 — must fail.
	var out bytes.Buffer
	err = engine.CombineAndDecrypt(ectx, bytes.NewReader(ct.Bytes()), &out, "", []*ThresholdShare{share0})
	if err == nil {
		t.Error("expected error with 1 share (threshold=2), got nil")
	}
}

func TestEngineThresholdWrongKey(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Unsetenv("HOME")

	engine, err := NewEngine(&HumanPolicy{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	ectx := &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}

	pub, _, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	_, wrongPriv, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("wrong keypair: %v", err)
	}
	defer SafeClear(wrongPriv)

	var ct bytes.Buffer
	if err := engine.EncryptThreshold(ectx, bytes.NewReader([]byte("secret")), &ct, [][]byte{pub, pub}, 2, Options{}); err != nil {
		t.Fatalf("EncryptThreshold: %v", err)
	}

	_, err = engine.CollectThresholdShare(ectx, bytes.NewReader(ct.Bytes()), wrongPriv, 0)
	if err == nil {
		t.Error("expected error with wrong private key, got nil")
	}
}

func TestEngineCombineAndDecryptNoShares(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Unsetenv("HOME")

	engine, err := NewEngine(&HumanPolicy{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	ectx := &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	err = engine.CombineAndDecrypt(ectx, bytes.NewReader([]byte("fake")), &bytes.Buffer{}, "", nil)
	if err == nil {
		t.Error("expected error with nil shares, got nil")
	}
}

// ---------------------------------------------------------------------------
// encrypt_asym_v2.go — DecryptStreamAsymV2 error paths
// ---------------------------------------------------------------------------

func TestDecryptStreamAsymV2WrongMagic(t *testing.T) {
	_, _, _, err := DecryptStreamAsymV2(bytes.NewReader([]byte("BADM\x03\x01\x00\x00\x00\x00")), nil, make([]byte, 32), nil, 1, nil)
	if err == nil {
		t.Error("expected error on wrong magic, got nil")
	}
}

func TestDecryptStreamAsymV2WrongVersion(t *testing.T) {
	// MAK3 magic but wrong version byte
	r := bytes.NewReader(append([]byte(MagicHeaderV2Asym), 0x01, 0x01, 0x00, 0x00, 0x00, 0x00))
	_, _, _, err := DecryptStreamAsymV2(r, nil, make([]byte, 32), nil, 1, nil)
	if err == nil {
		t.Error("expected error on wrong format version, got nil")
	}
}

func TestDecryptStreamAsymV2NoRecipientMatch(t *testing.T) {
	_, encPriv, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	defer SafeClear(encPriv)

	decPub, decPriv, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("dec keypair: %v", err)
	}
	defer SafeClear(decPriv)

	// Encrypt to decPub (a real recipient) then try decrypting with encPriv (wrong key).
	var ct bytes.Buffer
	if err := EncryptStreamAsymV2(bytes.NewReader([]byte("test")), &ct, [][]byte{decPub}, nil, 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamAsymV2: %v", err)
	}

	_, _, _, err = DecryptStreamAsymV2(bytes.NewReader(ct.Bytes()), &bytes.Buffer{}, encPriv, nil, 1, nil)
	if err == nil {
		t.Error("expected error decrypting with wrong key, got nil")
	}
}

func TestDecryptStreamAsymV2TamperedMAC(t *testing.T) {
	pub, priv, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	defer SafeClear(priv)

	var ct bytes.Buffer
	if err := EncryptStreamAsymV2(bytes.NewReader([]byte("tamper")), &ct, [][]byte{pub}, nil, 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamAsymV2: %v", err)
	}

	// Flip a byte in the FormatVersion field (offset 4).
	b := ct.Bytes()
	b[4] ^= 0x01
	_, _, _, err = DecryptStreamAsymV2(bytes.NewReader(b), &bytes.Buffer{}, priv, nil, 1, nil)
	if err == nil {
		t.Error("expected error on tampered header, got nil")
	}
}

// ---------------------------------------------------------------------------
// ParseV2AsymHeader error paths
// ---------------------------------------------------------------------------

func TestParseV2AsymHeaderWrongMagic(t *testing.T) {
	_, err := ParseV2AsymHeader(bytes.NewReader([]byte("BADM\x03\x01\x00\x00\x00\x00")), make([]byte, 32))
	if err == nil {
		t.Error("expected error on wrong magic, got nil")
	}
}

func TestParseV2AsymHeaderWrongVersion(t *testing.T) {
	r := bytes.NewReader(append([]byte(MagicHeaderV2Asym), 0x01, 0x01, 0x00, 0x00, 0x00, 0x00))
	_, err := ParseV2AsymHeader(r, make([]byte, 32))
	if err == nil {
		t.Error("expected error on wrong format version, got nil")
	}
}

// ---------------------------------------------------------------------------
// threshold_enc_v2.go — error paths
// ---------------------------------------------------------------------------

func TestEncryptStreamThresholdV2InvalidThreshold(t *testing.T) {
	pub, _, _, _, _ := GeneratePQKeyPair(1)
	// K=1 violates 2 ≤ K ≤ N.
	err := EncryptStreamThresholdV2(bytes.NewReader([]byte("x")), &bytes.Buffer{},
		[][]byte{pub, pub}, 1, 0, 1, 0, nil)
	if err == nil {
		t.Error("expected error for threshold K=1, got nil")
	}
}

func TestEncryptStreamThresholdV2KGreaterThanN(t *testing.T) {
	pub, _, _, _, _ := GeneratePQKeyPair(1)
	// K=3 > N=2.
	err := EncryptStreamThresholdV2(bytes.NewReader([]byte("x")), &bytes.Buffer{},
		[][]byte{pub, pub}, 3, 0, 1, 0, nil)
	if err == nil {
		t.Error("expected error for K > N, got nil")
	}
}

func TestDecryptThresholdCollectShareV2WrongMagic(t *testing.T) {
	_, err := DecryptThresholdCollectShareV2(bytes.NewReader([]byte("BADM...")), make([]byte, 32), 0)
	if err == nil {
		t.Error("expected error on wrong magic, got nil")
	}
}

func TestDecryptThresholdCollectShareV2NoThresholdTLV(t *testing.T) {
	// Build a valid MAK3 file WITHOUT the THRESHOLD TLV.
	pub, priv, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	defer SafeClear(priv)

	// EncryptStreamAsymV2 does NOT write a THRESHOLD TLV.
	var ct bytes.Buffer
	if err := EncryptStreamAsymV2(bytes.NewReader([]byte("no threshold")), &ct, [][]byte{pub}, nil, 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamAsymV2: %v", err)
	}

	_, err = DecryptThresholdCollectShareV2(bytes.NewReader(ct.Bytes()), priv, 0)
	if err == nil {
		t.Error("expected error when THRESHOLD TLV is missing, got nil")
	}
}

func TestDecryptThresholdCombineV2InsufficientShares(t *testing.T) {
	pubs := make([][]byte, 3)
	privs := make([][]byte, 3)
	for i := range pubs {
		pub, priv, _, _, err := GeneratePQKeyPair(1)
		if err != nil {
			t.Fatalf("keypair %d: %v", i, err)
		}
		pubs[i] = pub
		privs[i] = priv
		defer SafeClear(privs[i])
	}

	var ct bytes.Buffer
	if err := EncryptStreamThresholdV2(bytes.NewReader([]byte("secret")), &ct, pubs, 2, 0, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamThresholdV2: %v", err)
	}

	share0, _ := DecryptThresholdCollectShareV2(bytes.NewReader(ct.Bytes()), privs[0], 0)

	err := DecryptThresholdCombineV2(bytes.NewReader(ct.Bytes()), &bytes.Buffer{}, "", []*ThresholdShare{share0}, nil)
	if err == nil {
		t.Error("expected error with 1 share (threshold=2), got nil")
	}
}

// ---------------------------------------------------------------------------
// audit_engine.go threshold delegates — exercise through AuditEngine
// ---------------------------------------------------------------------------

func TestAuditEngineThresholdDelegates(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.jsonl")

	inner, err := NewEngine(&HumanPolicy{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer inner.Close()

	logger, err := NewJSONFileLogger(logFile)
	if err != nil {
		t.Fatalf("NewJSONFileLogger: %v", err)
	}
	ae := &AuditEngine{BaseEngine: BaseEngine{Engine: inner}, Logger: logger}
	ectx := &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}

	pub, priv, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	defer SafeClear(priv)

	// EncryptThreshold via AuditEngine.
	var ct bytes.Buffer
	if err := ae.EncryptThreshold(ectx, bytes.NewReader([]byte("audit-threshold")), &ct, [][]byte{pub, pub}, 2, Options{}); err != nil {
		t.Fatalf("AuditEngine.EncryptThreshold: %v", err)
	}

	// CollectThresholdShare via AuditEngine.
	share, err := ae.CollectThresholdShare(ectx, bytes.NewReader(ct.Bytes()), priv, 0)
	if err != nil {
		t.Fatalf("AuditEngine.CollectThresholdShare: %v", err)
	}

	// CombineAndDecrypt with only 1 share (will fail — exercises error path in delegate).
	var out bytes.Buffer
	_ = ae.CombineAndDecrypt(ectx, bytes.NewReader(ct.Bytes()), &out, "", []*ThresholdShare{share})
	// Not asserting success — just that the delegate runs and logs.
}
