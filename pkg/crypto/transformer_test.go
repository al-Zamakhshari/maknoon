package crypto

import (
	"bytes"
	"io"
	"testing"
)

// --- Pipeline ---

func TestPipelineEmpty(t *testing.T) {
	p := NewPipeline()
	var out bytes.Buffer
	if err := p.Execute(bytes.NewReader([]byte("passthrough")), &out); err != nil {
		t.Fatalf("empty pipeline: %v", err)
	}
	if out.String() != "passthrough" {
		t.Errorf("empty pipeline output = %q, want %q", out.String(), "passthrough")
	}
}

func TestPipelineSingleTransformer(t *testing.T) {
	// A transformer that uppercases nothing — just copies bytes through.
	p := NewPipeline(&identityTransformer{})
	input := []byte("single stage")
	var out bytes.Buffer
	if err := p.Execute(bytes.NewReader(input), &out); err != nil {
		t.Fatalf("single transformer pipeline: %v", err)
	}
	if !bytes.Equal(out.Bytes(), input) {
		t.Errorf("got %q, want %q", out.Bytes(), input)
	}
}

func TestPipelineMultipleTransformers(t *testing.T) {
	// Two identity transformers chained: bytes should still pass through unchanged.
	p := NewPipeline(&identityTransformer{}, &identityTransformer{})
	input := []byte("chained")
	var out bytes.Buffer
	if err := p.Execute(bytes.NewReader(input), &out); err != nil {
		t.Fatalf("chained pipeline: %v", err)
	}
	if !bytes.Equal(out.Bytes(), input) {
		t.Errorf("chained pipeline: got %q, want %q", out.Bytes(), input)
	}
}

// --- ZstdTransformer ---

func TestZstdTransformerRoundTrip(t *testing.T) {
	input := bytes.Repeat([]byte("compressible data block "), 100)

	// Compress.
	var compressed bytes.Buffer
	enc := &ZstdTransformer{IsDecompress: false}
	if err := enc.Transform(bytes.NewReader(input), &compressed); err != nil {
		t.Fatalf("compress: %v", err)
	}

	// Verify compressed is smaller.
	if compressed.Len() >= len(input) {
		t.Logf("note: compressed (%d) not smaller than input (%d) — data may not compress well", compressed.Len(), len(input))
	}

	// Decompress.
	var recovered bytes.Buffer
	dec := &ZstdTransformer{IsDecompress: true}
	if err := dec.Transform(bytes.NewReader(compressed.Bytes()), &recovered); err != nil {
		t.Fatalf("decompress: %v", err)
	}

	if !bytes.Equal(recovered.Bytes(), input) {
		t.Error("zstd round-trip: recovered bytes do not match original")
	}
}

// --- AEADTransformer (passphrase path) ---

func TestAEADTransformerEncryptDecryptPassphrase(t *testing.T) {
	pass := []byte("aead-transformer-pass")
	profile := DefaultProfile()
	input := []byte("aead transformer encryption test")

	// Encrypt.
	var ct bytes.Buffer
	enc := &AEADTransformer{
		Passphrase:  pass,
		Profile:     profile,
		Concurrency: 1,
	}
	if err := enc.Transform(bytes.NewReader(input), &ct); err != nil {
		t.Fatalf("AEADTransformer encrypt: %v", err)
	}

	// Decrypt. EncryptStreamNoHeader omits the magic header, so stealth=true.
	var plain bytes.Buffer
	dec := &AEADTransformer{
		Passphrase:  pass,
		Profile:     profile,
		Concurrency: 1,
		IsDecrypt:   true,
		Stealth:     true,
	}
	if err := dec.Transform(bytes.NewReader(ct.Bytes()), &plain); err != nil {
		t.Fatalf("AEADTransformer decrypt: %v", err)
	}

	if !bytes.Equal(plain.Bytes(), input) {
		t.Errorf("AEAD round-trip mismatch: got %q, want %q", plain.Bytes(), input)
	}
}

func TestAEADTransformerEncryptWithPrivKey(t *testing.T) {
	_, kemPriv, _, _, _ := GeneratePQKeyPair(1)
	kemPub, _, _, _, _ := GeneratePQKeyPair(1)
	_ = kemPriv

	// Encrypt to a recipient public key.
	input := []byte("asymmetric aead test")
	var ct bytes.Buffer
	enc := &AEADTransformer{
		RecipientPK: [][]byte{kemPub},
		Profile:     DefaultProfile(),
		Concurrency: 1,
	}
	if err := enc.Transform(bytes.NewReader(input), &ct); err != nil {
		t.Fatalf("AEADTransformer public key encrypt: %v", err)
	}
	if ct.Len() == 0 {
		t.Error("expected non-empty ciphertext")
	}
}

// identityTransformer is a test Transformer that passes bytes through unchanged.
type identityTransformer struct{}

func (i *identityTransformer) Transform(r io.Reader, w io.Writer) error {
	_, err := io.Copy(w, r)
	return err
}
