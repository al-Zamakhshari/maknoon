package crypto

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// --- TLV encoding/decoding ---

func TestTLVRoundtrip(t *testing.T) {
	entries := []TLVEntry{
		{Tag: TLVTagChunkSize, Value: []byte{0x00, 0x00, 0x01, 0x00}}, // 65536 LE
		{Tag: TLVTagFilename, Value: []byte("secret.pdf")},
		{Tag: TLVTagSenderID, Value: []byte{0xde, 0xad, 0xbe, 0xef}},
	}
	encoded := EncodeTLVs(entries)
	decoded := DecodeTLVs(encoded)

	if len(decoded) != len(entries) {
		t.Fatalf("decoded %d entries, want %d", len(decoded), len(entries))
	}
	for i, want := range entries {
		got := decoded[i]
		if got.Tag != want.Tag {
			t.Errorf("[%d] tag: got 0x%04x, want 0x%04x", i, got.Tag, want.Tag)
		}
		if !bytes.Equal(got.Value, want.Value) {
			t.Errorf("[%d] value mismatch: got %x, want %x", i, got.Value, want.Value)
		}
	}
}

func TestTLVEmpty(t *testing.T) {
	if b := EncodeTLVs(nil); b != nil {
		t.Errorf("EncodeTLVs(nil) = %v, want nil", b)
	}
	if entries := DecodeTLVs(nil); len(entries) != 0 {
		t.Errorf("DecodeTLVs(nil) = %v, want empty", entries)
	}
}

func TestTLVUnknownTagPreserved(t *testing.T) {
	// An unknown tag (0xFFFF) must be round-tripped unchanged.
	entries := []TLVEntry{
		{Tag: 0xFFFF, Value: []byte("future extension")},
		{Tag: TLVTagFilename, Value: []byte("file.txt")},
	}
	decoded := DecodeTLVs(EncodeTLVs(entries))
	if len(decoded) != 2 {
		t.Fatalf("got %d entries, want 2", len(decoded))
	}
	if decoded[0].Tag != 0xFFFF {
		t.Errorf("unknown tag not preserved: got 0x%04x", decoded[0].Tag)
	}
}

func TestTLVTruncatedSilentlyIgnored(t *testing.T) {
	// A TLV block that ends mid-value should not panic; it should just stop decoding.
	bad := []byte{0x01, 0x00, 0x10, 0x00} // tag=1, length=16, but no value bytes
	decoded := DecodeTLVs(bad)
	if len(decoded) != 0 {
		t.Errorf("expected 0 entries from truncated TLV, got %d", len(decoded))
	}
}

func TestFindTLV(t *testing.T) {
	entries := []TLVEntry{
		{Tag: TLVTagFilename, Value: []byte("report.pdf")},
		{Tag: TLVTagChunkSize, Value: []byte{0, 0, 1, 0}},
	}
	got := FindTLV(entries, TLVTagFilename)
	if string(got) != "report.pdf" {
		t.Errorf("FindTLV filename: got %q", got)
	}
	if FindTLV(entries, 0xDEAD) != nil {
		t.Error("FindTLV for absent tag should return nil")
	}
}

// --- Header MAC ---

func TestHeaderMACBasic(t *testing.T) {
	fek := make([]byte, 32)
	for i := range fek {
		fek[i] = byte(i + 1)
	}
	hdr := []byte("MAK2\x02\x01\x00\x00\x00\x00\x20" + strings.Repeat("\xAA", 32+12))

	mac := ComputeHeaderMAC(fek, hdr)
	if len(mac) != 32 {
		t.Fatalf("MAC length %d, want 32", len(mac))
	}
	if !VerifyHeaderMAC(fek, hdr, mac) {
		t.Fatal("VerifyHeaderMAC failed on correct input")
	}
}

func TestHeaderMACTamperedHeader(t *testing.T) {
	fek := make([]byte, 32)
	hdr := []byte("MAK2\x02\x01\x00\x00\x00\x00\x20" + strings.Repeat("\xBB", 44))
	mac := ComputeHeaderMAC(fek, hdr)

	// Flip one byte in the header.
	tampered := make([]byte, len(hdr))
	copy(tampered, hdr)
	tampered[5] ^= 0xFF

	if VerifyHeaderMAC(fek, tampered, mac) {
		t.Error("VerifyHeaderMAC should fail on tampered header")
	}
}

func TestHeaderMACWrongKey(t *testing.T) {
	fek1 := make([]byte, 32)
	fek2 := make([]byte, 32)
	for i := range fek2 {
		fek2[i] = 0xFF
	}
	hdr := []byte("MAK2test header bytes")
	mac := ComputeHeaderMAC(fek1, hdr)
	if VerifyHeaderMAC(fek2, hdr, mac) {
		t.Error("VerifyHeaderMAC should fail with wrong key")
	}
}

// --- V2 symmetric encrypt/decrypt round-trip ---

func TestV2SymmetricRoundtrip(t *testing.T) {
	plain := []byte("V2 symmetric encryption round-trip test payload 🔐")
	passphrase := []byte("test-passphrase-v2")

	// Encrypt.
	var ct bytes.Buffer
	err := EncryptStreamV2(bytes.NewReader(plain), &ct, passphrase, 0, nil, 1, 0, nil)
	if err != nil {
		t.Fatalf("EncryptStreamV2: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatal("ciphertext is empty")
	}

	// Verify magic.
	header := ct.Bytes()
	if string(header[:4]) != MagicHeaderV2Sym {
		t.Errorf("magic mismatch: got %q, want %q", string(header[:4]), MagicHeaderV2Sym)
	}
	if header[4] != FormatVersionV2Sym {
		t.Errorf("format version: got %d, want %d", header[4], FormatVersionV2Sym)
	}

	// Decrypt.
	var out bytes.Buffer
	_, _, _, err = DecryptStreamV2(bytes.NewReader(ct.Bytes()), &out, passphrase, 1, nil)
	if err != nil {
		t.Fatalf("DecryptStreamV2: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Errorf("plaintext mismatch\ngot:  %q\nwant: %q", out.Bytes(), plain)
	}
}

func TestV2WrongPassphraseFails(t *testing.T) {
	plain := []byte("secret")
	var ct bytes.Buffer
	if err := EncryptStreamV2(bytes.NewReader(plain), &ct, []byte("correct"), 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamV2: %v", err)
	}
	var out bytes.Buffer
	_, _, _, err := DecryptStreamV2(bytes.NewReader(ct.Bytes()), &out, []byte("wrong-password"), 1, nil)
	if err == nil {
		t.Fatal("expected error with wrong passphrase, got nil")
	}
}

func TestV2TLVRoundtrip(t *testing.T) {
	plain := []byte("file with metadata")
	pass := []byte("pass")

	tlvs := []TLVEntry{
		{Tag: TLVTagFilename, Value: []byte("report.pdf")},
		{Tag: TLVTagSenderID, Value: []byte{0x01, 0x02, 0x03, 0x04}},
	}

	var ct bytes.Buffer
	if err := EncryptStreamV2(bytes.NewReader(plain), &ct, pass, 0, tlvs, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamV2: %v", err)
	}

	var out bytes.Buffer
	_, _, decTLVs, err := DecryptStreamV2(bytes.NewReader(ct.Bytes()), &out, pass, 1, nil)
	if err != nil {
		t.Fatalf("DecryptStreamV2: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Errorf("plaintext mismatch")
	}

	fname := FindTLV(decTLVs, TLVTagFilename)
	if string(fname) != "report.pdf" {
		t.Errorf("filename TLV: got %q, want %q", string(fname), "report.pdf")
	}
	sid := FindTLV(decTLVs, TLVTagSenderID)
	if !bytes.Equal(sid, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("sender ID TLV mismatch: got %x", sid)
	}
}

// --- Truncation detection ---

func TestV2TruncationDetected(t *testing.T) {
	plain := make([]byte, 200*1024) // 200 KB — spans multiple chunks
	for i := range plain {
		plain[i] = byte(i)
	}
	pass := []byte("trunc-test")

	var ct bytes.Buffer
	if err := EncryptStreamV2(bytes.NewReader(plain), &ct, pass, 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamV2: %v", err)
	}

	// Truncate: remove the last 50 bytes (deletes terminator + part of last chunk).
	truncated := ct.Bytes()[:ct.Len()-50]
	var out bytes.Buffer
	_, _, _, err := DecryptStreamV2(bytes.NewReader(truncated), &out, pass, 1, nil)
	if err == nil {
		t.Error("expected error on truncated V2 file, got nil")
	}
}

func TestV2TerminatorRequired(t *testing.T) {
	// Build a V1-like chunk stream without a terminator, then try DecryptStreamV2.
	// The header will have MAK2 magic but missing terminator after the last chunk.
	plain := []byte("no terminator")
	pass := []byte("pass")
	var ct bytes.Buffer
	if err := EncryptStreamV2(bytes.NewReader(plain), &ct, pass, 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamV2: %v", err)
	}

	// Strip last 4 bytes (the terminator 0x00000000).
	stripped := ct.Bytes()[:ct.Len()-4]
	var out bytes.Buffer
	_, _, _, err := DecryptStreamV2(bytes.NewReader(stripped), &out, pass, 1, nil)
	if err == nil {
		t.Error("expected error when terminator is missing, got nil")
	}
}

// --- HeaderMAC tamper detection end-to-end ---

func TestV2TamperedHeaderDetected(t *testing.T) {
	plain := []byte("tamper test payload")
	pass := []byte("pass")
	var ct bytes.Buffer
	if err := EncryptStreamV2(bytes.NewReader(plain), &ct, pass, 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamV2: %v", err)
	}

	// Flip a byte in the FormatVersion field (offset 4).
	tampered := ct.Bytes()
	tampered[4] ^= 0x01

	var out bytes.Buffer
	_, _, _, err := DecryptStreamV2(bytes.NewReader(tampered), &out, pass, 1, nil)
	if err == nil {
		t.Error("expected error on tampered header, got nil")
	}
}

// --- V1 backward compatibility ---

func TestV1FilesStillDecrypt(t *testing.T) {
	plain := []byte("V1 backward compat test — must still work after V2 introduction")
	pass := []byte("v1-pass")

	// Encrypt as V1.
	var ct bytes.Buffer
	if err := EncryptStream(bytes.NewReader(plain), &ct, pass, FlagNone, 1, 0); err != nil {
		t.Fatalf("EncryptStream (V1): %v", err)
	}
	if string(ct.Bytes()[:4]) != MagicHeaderSym {
		t.Fatalf("V1 magic mismatch: got %q", string(ct.Bytes()[:4]))
	}

	// Decrypt using the V1 path.
	var out bytes.Buffer
	pid, flags, err := DecryptStream(bytes.NewReader(ct.Bytes()), &out, pass, 1, false)
	if err != nil {
		t.Fatalf("DecryptStream (V1): %v", err)
	}
	if pid != 1 {
		t.Errorf("profile ID: got %d, want 1", pid)
	}
	_ = flags
	if !bytes.Equal(out.Bytes(), plain) {
		t.Errorf("V1 plaintext mismatch\ngot:  %q\nwant: %q", out.Bytes(), plain)
	}
}

// --- V2 magic detection from ReadHeader ---

func TestReadHeaderDetectsV2Magic(t *testing.T) {
	// Create a V2 file and verify ReadHeader returns the V2 magic without error
	// so the caller can dispatch to the V2 decode path.
	plain := []byte("dispatch test")
	pass := []byte("p")
	var ct bytes.Buffer
	if err := EncryptStreamV2(bytes.NewReader(plain), &ct, pass, 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamV2: %v", err)
	}

	magic, _, _, _, err := ReadHeader(bytes.NewReader(ct.Bytes()), false)
	if err != nil {
		t.Fatalf("ReadHeader on V2 file returned error: %v", err)
	}
	if magic != MagicHeaderV2Sym {
		t.Errorf("magic = %q, want %q", magic, MagicHeaderV2Sym)
	}
}

// --- V2 empty plaintext ---

func TestV2EmptyPlaintext(t *testing.T) {
	pass := []byte("empty")
	var ct bytes.Buffer
	if err := EncryptStreamV2(bytes.NewReader([]byte{}), &ct, pass, 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamV2 empty: %v", err)
	}

	// Verify we have the terminator at least.
	b := ct.Bytes()
	if len(b) < 4 {
		t.Fatalf("ciphertext too short: %d bytes", len(b))
	}
	lastFour := b[len(b)-4:]
	if binary.LittleEndian.Uint32(lastFour) != 0 {
		t.Errorf("terminator not found at end: %x", lastFour)
	}

	var out bytes.Buffer
	_, _, _, err := DecryptStreamV2(bytes.NewReader(ct.Bytes()), &out, pass, 1, nil)
	if err != nil {
		t.Fatalf("DecryptStreamV2 empty: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("expected empty output, got %d bytes", out.Len())
	}
}

// --- V2 asymmetric (MAK3) round-trip ---

func TestV2AsymmetricRoundtrip(t *testing.T) {
	kemPub, kemPriv, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}
	defer SafeClear(kemPriv)

	plain := []byte("V2 asymmetric MAK3 round-trip 🔐")

	var ct bytes.Buffer
	err = EncryptStreamAsymV2(bytes.NewReader(plain), &ct, [][]byte{kemPub}, nil, 0, 0, nil, 1, 0, nil)
	if err != nil {
		t.Fatalf("EncryptStreamAsymV2: %v", err)
	}

	// Verify magic.
	if string(ct.Bytes()[:4]) != MagicHeaderV2Asym {
		t.Errorf("magic = %q, want %q", string(ct.Bytes()[:4]), MagicHeaderV2Asym)
	}

	var out bytes.Buffer
	_, _, _, err = DecryptStreamAsymV2(bytes.NewReader(ct.Bytes()), &out, kemPriv, nil, 1, nil)
	if err != nil {
		t.Fatalf("DecryptStreamAsymV2: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Errorf("plaintext mismatch\ngot:  %q\nwant: %q", out.Bytes(), plain)
	}
}

func TestV2AsymmetricWrongKeyFails(t *testing.T) {
	kemPub, _, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}
	_, wrongPriv, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair (wrong): %v", err)
	}
	defer SafeClear(wrongPriv)

	var ct bytes.Buffer
	if err = EncryptStreamAsymV2(bytes.NewReader([]byte("secret")), &ct, [][]byte{kemPub}, nil, 0, 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamAsymV2: %v", err)
	}

	var out bytes.Buffer
	_, _, _, err = DecryptStreamAsymV2(bytes.NewReader(ct.Bytes()), &out, wrongPriv, nil, 1, nil)
	if err == nil {
		t.Error("expected error with wrong private key, got nil")
	}
}

func TestV2AsymmetricMultiRecipient(t *testing.T) {
	kemPub0, kemPriv0, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("keypair 0: %v", err)
	}
	kemPub1, kemPriv1, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("keypair 1: %v", err)
	}
	defer SafeClear(kemPriv0)
	defer SafeClear(kemPriv1)

	plain := []byte("two recipients — either can decrypt")

	var ct bytes.Buffer
	if err = EncryptStreamAsymV2(bytes.NewReader(plain), &ct, [][]byte{kemPub0, kemPub1}, nil, 0, 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamAsymV2: %v", err)
	}

	// Recipient 0 can decrypt.
	var out0 bytes.Buffer
	if _, _, _, err = DecryptStreamAsymV2(bytes.NewReader(ct.Bytes()), &out0, kemPriv0, nil, 1, nil); err != nil {
		t.Fatalf("decrypt with key 0: %v", err)
	}
	if !bytes.Equal(out0.Bytes(), plain) {
		t.Error("key 0 plaintext mismatch")
	}

	// Recipient 1 can decrypt.
	var out1 bytes.Buffer
	if _, _, _, err = DecryptStreamAsymV2(bytes.NewReader(ct.Bytes()), &out1, kemPriv1, nil, 1, nil); err != nil {
		t.Fatalf("decrypt with key 1: %v", err)
	}
	if !bytes.Equal(out1.Bytes(), plain) {
		t.Error("key 1 plaintext mismatch")
	}
}

// TestV2AutoDispatch verifies that the existing DecryptStream / DecryptStreamWithPrivateKey
// functions automatically detect and handle V2 files via the MAK2/MAK3 dispatch path.
func TestV2AutoDispatch(t *testing.T) {
	// Symmetric auto-dispatch.
	plain := []byte("auto-dispatch symmetric")
	pass := []byte("p")
	var ct bytes.Buffer
	if err := EncryptStreamV2(bytes.NewReader(plain), &ct, pass, 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamV2: %v", err)
	}
	var out bytes.Buffer
	if _, _, err := DecryptStream(bytes.NewReader(ct.Bytes()), &out, pass, 1, false); err != nil {
		t.Fatalf("DecryptStream auto-dispatch V2: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Error("symmetric auto-dispatch plaintext mismatch")
	}

	// Asymmetric auto-dispatch.
	kemPub, kemPriv, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}
	defer SafeClear(kemPriv)

	plainAsym := []byte("auto-dispatch asymmetric")
	var ctAsym bytes.Buffer
	if err = EncryptStreamAsymV2(bytes.NewReader(plainAsym), &ctAsym, [][]byte{kemPub}, nil, 0, 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamAsymV2: %v", err)
	}
	var outAsym bytes.Buffer
	if _, _, err = DecryptStreamWithPrivateKey(bytes.NewReader(ctAsym.Bytes()), &outAsym, kemPriv, nil, 1, false); err != nil {
		t.Fatalf("DecryptStreamWithPrivateKey auto-dispatch V2: %v", err)
	}
	if !bytes.Equal(outAsym.Bytes(), plainAsym) {
		t.Error("asymmetric auto-dispatch plaintext mismatch")
	}
}

// TestV2AsymmetricTamperHeaderFails verifies that tampering with the MAK3 header
// is detected via the HeaderMAC.
func TestV2AsymmetricTamperHeaderFails(t *testing.T) {
	kemPub, kemPriv, _, _, err := GeneratePQKeyPair(1)
	if err != nil {
		t.Fatalf("GeneratePQKeyPair: %v", err)
	}
	defer SafeClear(kemPriv)

	var ct bytes.Buffer
	if err = EncryptStreamAsymV2(bytes.NewReader([]byte("tamper asym")), &ct, [][]byte{kemPub}, nil, 0, 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamAsymV2: %v", err)
	}

	// Flip a byte in the format version field (offset 4).
	tampered := ct.Bytes()
	tampered[4] ^= 0x01

	var out bytes.Buffer
	_, _, _, err = DecryptStreamAsymV2(bytes.NewReader(tampered), &out, kemPriv, nil, 1, nil)
	if err == nil {
		t.Error("expected error on tampered MAK3 header, got nil")
	}
}

// --- V2 large file (multi-chunk) ---

func TestV2LargeFileBoundary(t *testing.T) {
	// Test a file that spans exactly 3 chunks.
	chunkPlain := ChunkSize - 16 // one full AES-GCM plaintext chunk
	plain := make([]byte, 3*chunkPlain)
	for i := range plain {
		plain[i] = byte(i & 0xFF)
	}
	pass := []byte("large-file")

	var ct bytes.Buffer
	if err := EncryptStreamV2(bytes.NewReader(plain), &ct, pass, 0, nil, 1, 0, nil); err != nil {
		t.Fatalf("EncryptStreamV2 large: %v", err)
	}

	var out bytes.Buffer
	_, _, _, err := DecryptStreamV2(bytes.NewReader(ct.Bytes()), &out, pass, 1, nil)
	if err != nil {
		t.Fatalf("DecryptStreamV2 large: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Errorf("large file plaintext mismatch (%d vs %d bytes)", out.Len(), len(plain))
	}
}
