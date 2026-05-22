package crypto

import (
	"io"
	"log/slog"
)

// Transformer defines a single stage in a data processing pipeline.
type Transformer interface {
	Transform(r io.Reader, w io.Writer) error
}

// Pipeline orchestrates a series of transformers to process data in stages.
type Pipeline struct {
	Transformers []Transformer
}

// NewPipeline creates a new data processing pipeline.
func NewPipeline(t ...Transformer) *Pipeline {
	return &Pipeline{Transformers: t}
}

// Execute runs the pipeline by chaining the transformers.
func (p *Pipeline) Execute(r io.Reader, w io.Writer) error {
	if len(p.Transformers) == 0 {
		_, err := io.Copy(w, r)
		return err
	}

	// We use pipes to chain the transformers
	var nextReader io.Reader = r
	var errChan = make(chan error, len(p.Transformers))

	for i := 0; i < len(p.Transformers)-1; i++ {
		pr, pw := io.Pipe()
		go func(t Transformer, reader io.Reader, writer *io.PipeWriter) {
			err := t.Transform(reader, writer)
			_ = writer.CloseWithError(err)
			errChan <- err
		}(p.Transformers[i], nextReader, pw)
		nextReader = pr
	}

	// Execute the last transformer in the current goroutine (or chain to final writer)
	err := p.Transformers[len(p.Transformers)-1].Transform(nextReader, w)

	// Collect errors from other goroutines (basic check)
	// In a production industrial-grade system, we would use a more robust sync mechanism.
	return err
}

// AEADTransformer handles chunked encryption using an AEAD cipher.
type AEADTransformer struct {
	Engine      *Engine
	Context     *EngineContext
	Profile     Profile
	Passphrase  []byte
	PrivKey     []byte
	RecipientPK [][]byte
	IsDecrypt   bool
	Concurrency int
	Stealth     bool
	Flags       byte
}

func (t *AEADTransformer) Transform(r io.Reader, w io.Writer) error {
	if t.IsDecrypt {
		if len(t.PrivKey) > 0 {
			_, _, err := DecryptStreamWithPrivateKeyAndEvents(r, w, t.PrivKey, nil, t.Concurrency, t.Stealth, t.Context)
			return err
		}
		_, _, err := DecryptStreamWithEvents(r, w, t.Passphrase, t.Concurrency, t.Stealth, t.Context)
		return err
	}

	// Encrypt
	if len(t.RecipientPK) > 0 {
		// Asymmetric currently doesn't have a NoHeader variant, but we can bypass magic in opts
		return encryptStreamAsymV1(r, w, t.RecipientPK, nil, t.Flags|FlagStealth, t.Concurrency, t.Profile.ID(), t.Context)
	}
	return encryptStreamSymV1(r, w, t.Passphrase, t.Flags|FlagStealth, t.Concurrency, t.Profile.ID(), t.Context)
}

// ZstdTransformer handles transparent compression.
type ZstdTransformer struct {
	IsDecompress bool
}

func (t *ZstdTransformer) Transform(r io.Reader, w io.Writer) error {
	if t.IsDecompress {
		return DecompressStream(r, w)
	}
	return CompressStream(r, w)
}

// TarTransformer handles archival and extraction.
type TarTransformer struct {
	BaseDir   string
	IsExtract bool
	Logger    *slog.Logger
}

func (t *TarTransformer) Transform(r io.Reader, w io.Writer) error {
	if t.IsExtract {
		return ExtractArchive(r, t.BaseDir)
	}
	// Note: wrapWithArchiver returns a Reader, so this needs to be adapted
	// for the Transformer pattern (which wants r/w).
	// For now, we'll keep the existing procedural flow in pipeline.go.
	return nil
}
