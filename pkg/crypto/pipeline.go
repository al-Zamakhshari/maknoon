package crypto

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Transformer defines an interchangeable middleware for the crypto pipeline.
type Transformer interface {
	Wrap(r io.Reader) (io.Reader, error)
}

// ArchiveTransformer handles TAR archiving and extraction.
type ArchiveTransformer struct {
	InputPath string
	OutputDir string // Set for extraction
	Logger    *slog.Logger
}

func (t *ArchiveTransformer) Wrap(r io.Reader) (io.Reader, error) {
	if t.OutputDir != "" {
		// Extraction is a Sink in our current design, it doesn't return a reader easily.
		// For now, keep ExtractArchive as a separate helper or refactor later.
		return r, ExtractArchive(r, t.OutputDir)
	}
	if t.Logger != nil {
		t.Logger.Info("archiving input directory", "path", t.InputPath)
	}
	return wrapWithArchiver(t.InputPath, t.Logger), nil
}

// CompressTransformer handles Zstd compression and decompression.
type CompressTransformer struct {
	Decompress bool
	Logger     *slog.Logger
}

func (t *CompressTransformer) Wrap(r io.Reader) (io.Reader, error) {
	if t.Decompress {
		if t.Logger != nil {
			t.Logger.Info("decompressing zstd stream")
		}
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		return zr, nil
	}
	if t.Logger != nil {
		t.Logger.Info("enabling zstd compression")
	}
	return wrapWithCompressor(r, t.Logger), nil
}

// EncryptTransformer handles the core cryptographic pipeline.
type EncryptTransformer struct {
	Options Options
}

func (t *EncryptTransformer) Wrap(r io.Reader) (io.Reader, error) {
	pr, pw := io.Pipe()
	var flags byte
	if t.Options.Compress {
		flags |= FlagCompress
	}
	if t.Options.IsArchive {
		flags |= FlagArchive
	}
	if t.Options.Stealth {
		flags |= FlagStealth
	}

	allPublicKeys := t.Options.PublicKeys
	if len(t.Options.PublicKey) > 0 {
		allPublicKeys = append(allPublicKeys, t.Options.PublicKey)
	}

	var logger *slog.Logger
	if t.Options.Verbose {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	go func() {
		defer pw.Close()
		var err error
		if len(allPublicKeys) > 0 {
			if logger != nil {
				logger.Info("starting asymmetric encryption", "recipients", len(allPublicKeys))
			}
			err = EncryptStreamWithPublicKeysAndEvents(r, pw, allPublicKeys, t.Options.SigningKey, flags, t.Options.Concurrency, t.Options.ProfileID, t.Options.EventStream)
		} else {
			if logger != nil {
				logger.Info("starting symmetric encryption")
			}
			err = EncryptStreamWithEvents(r, pw, t.Options.Passphrase, flags, t.Options.Concurrency, t.Options.ProfileID, t.Options.EventStream)
		}

		if err != nil {
			_ = pw.CloseWithError(err)
		} else {
			t.Options.emit(EventHandshakeComplete{})
		}
	}()

	return pr, nil
}

// DecryptTransformer handles the core unprotection pipeline.
type DecryptTransformer struct {
	Options Options
	Input   io.Reader
	Magic   string
}

func (t *DecryptTransformer) Wrap(r io.Reader) (io.Reader, error) {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		var dErr error
		if t.Magic == MagicHeaderAsym {
			_, _, dErr = DecryptStreamWithPrivateKeyAndEvents(t.Input, pw, t.Options.Passphrase, t.Options.PublicKey, t.Options.Concurrency, t.Options.Stealth, t.Options.EventStream)
		} else {
			_, _, dErr = DecryptStreamWithEvents(t.Input, pw, t.Options.Passphrase, t.Options.Concurrency, t.Options.Stealth, t.Options.EventStream)
		}

		if dErr != nil {
			_ = pw.CloseWithError(dErr)
		} else {
			t.Options.emit(EventHandshakeComplete{})
		}
	}()
	return pr, nil
}

// Options defines settings for the protection process.
type Options struct {
	Passphrase     []byte
	PublicKey      []byte   // Deprecated: use PublicKeys
	PublicKeys     [][]byte // Supports multi-recipient encryption
	SigningKey     []byte   // ML-DSA private key for integrated signing
	ProfileID      byte     // 0 for default
	Compress       bool
	IsArchive      bool
	Concurrency    int                // 0 for auto (NumCPU), 1 for sequential
	TotalSize      int64              // Known total size of input for progress tracking
	EventStream    chan<- EngineEvent // Optional channel for telemetry
	ProgressReader io.Reader          // Deprecated: use EventStream
	Verbose        bool               // Enables internal slog tracing
	Stealth        bool               // Enables fingerprint resistance (headerless)
}

func (o *Options) emit(ev EngineEvent) {
	if o.EventStream != nil {
		o.EventStream <- ev
	}
}

// Protect handles the full encryption pipeline under the active policy.
func (e *Engine) Protect(inputName string, r io.Reader, w io.Writer, opts Options) (byte, error) {
	// 1. Enforce Path Policy
	if inputName != "-" && inputName != "" {
		if err := e.Policy.ValidatePath(inputName); err != nil {
			return 0, err
		}
	}

	// 2. Clamp Resources
	opts.Concurrency = e.Policy.ClampConcurrency(opts.Concurrency, e.Config.AgentLimits.MaxWorkers)

	// 3. Delegation to core implementation
	return protectInternal(inputName, r, w, opts)
}

func protectInternal(inputName string, r io.Reader, w io.Writer, opts Options) (byte, error) {
	var logger *slog.Logger
	if opts.Verbose {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	} else {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	var flags byte
	if opts.IsArchive {
		flags |= FlagArchive
	}
	if opts.Compress {
		flags |= FlagCompress
	}
	if opts.Stealth {
		logger.Info("enabling stealth mode (headerless)")
		flags |= FlagStealth
	}

	var totalBytes int64
	if inputName != "-" && inputName != "" {
		if fi, err := os.Stat(inputName); err == nil && !fi.IsDir() {
			totalBytes = fi.Size()
		}
	}
	opts.emit(EventEncryptionStarted{TotalBytes: totalBytes})

	sourceReader := r
	if sourceReader == nil && !opts.IsArchive {
		if inputName == "-" {
			sourceReader = os.Stdin
		} else {
			f, err := os.Open(inputName)
			if err != nil {
				return 0, fmt.Errorf("failed to open input file: %w", err)
			}
			defer func() { _ = f.Close() }()
			sourceReader = f
		}
	}

	// Build the pipeline chain
	var transformers []Transformer
	if opts.IsArchive {
		transformers = append(transformers, &ArchiveTransformer{InputPath: inputName, Logger: logger})
	}
	if opts.ProgressReader != nil {
		if wr, ok := opts.ProgressReader.(io.Writer); ok {
			sourceReader = io.TeeReader(sourceReader, wr)
		}
	}
	if opts.Compress {
		transformers = append(transformers, &CompressTransformer{Logger: logger})
	}
	transformers = append(transformers, &EncryptTransformer{Options: opts})

	currentReader := sourceReader
	for _, t := range transformers {
		var err error
		currentReader, err = t.Wrap(currentReader)
		if err != nil {
			return 0, err
		}
	}

	_, err := io.Copy(w, currentReader)
	return flags, err
}

// Unprotect handles the full decryption pipeline: Handshake -> Decrypt -> Decompress -> Extract.
func (e *Engine) Unprotect(r io.Reader, w io.Writer, outPath string, opts Options) (byte, error) {
	// 1. Enforce Path Policy
	if outPath != "-" && outPath != "" {
		if err := e.Policy.ValidatePath(outPath); err != nil {
			return 0, err
		}
	}

	// 2. Clamp Resources
	opts.Concurrency = e.Policy.ClampConcurrency(opts.Concurrency, e.Config.AgentLimits.MaxWorkers)

	// 3. Delegation to core implementation
	return unprotectInternal(r, w, outPath, opts)
}

func unprotectInternal(r io.Reader, w io.Writer, outPath string, opts Options) (byte, error) {
	var logger *slog.Logger
	if opts.Verbose {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	} else {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	opts.emit(EventDecryptionStarted{TotalBytes: opts.TotalSize})

	// 1. Peek at the header to get flags (compression, archive, etc.)
	magic, profileID, flags, recipientCount, err := ReadHeader(r, opts.Stealth)
	if err != nil {
		return 0, fmt.Errorf("failed to read file header: %w", err)
	}

	// 2. Wrap reader with multi-reader since we peeked
	var headerBytes []byte
	if !opts.Stealth {
		headerBytes = append([]byte(magic), profileID, flags)
		if magic == MagicHeaderAsym {
			headerBytes = append(headerBytes, recipientCount)
		}
	} else {
		headerBytes = []byte{profileID, flags}
	}
	fullIn := io.MultiReader(bytes.NewReader(headerBytes), r)

	// 3. Build the pipeline chain
	var transformers []Transformer
	transformers = append(transformers, &DecryptTransformer{Options: opts, Input: fullIn, Magic: magic})

	if flags&FlagCompress != 0 {
		transformers = append(transformers, &CompressTransformer{Decompress: true, Logger: logger})
	}

	currentReader := (io.Reader)(nil) // Initial reader for first transformer
	for _, t := range transformers {
		var err error
		currentReader, err = t.Wrap(currentReader)
		if err != nil {
			return flags, err
		}
	}

	// 4. Finalize: Extract Archive or write to file/writer
	if flags&FlagArchive != 0 {
		logger.Info("extracting tar archive", "target", outPath)
		if err := ExtractArchive(currentReader, outPath); err != nil {
			return flags, fmt.Errorf("failed to extract archive: %w", err)
		}
		return flags, nil
	}

	var out io.Writer
	if w != nil {
		out = w
	} else if outPath == "-" {
		out = os.Stdout
	} else {
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return flags, err
		}
		f, err := os.Create(outPath)
		if err != nil {
			return flags, fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	_, err = io.Copy(out, currentReader)
	return flags, err
}

// --- Legacy Shims ---

// Protect handles the full encryption pipeline for a source (file, directory, or reader).
// This is a shim that uses a default HumanPolicy engine.
func Protect(inputName string, r io.Reader, w io.Writer, opts Options) (byte, error) {
	return protectInternal(inputName, r, w, opts)
}

// Unprotect handles the full decryption pipeline: Handshake -> Decrypt -> Decompress -> Extract.
// This is a shim that uses a default HumanPolicy engine.
func Unprotect(r io.Reader, w io.Writer, outPath string, opts Options) (byte, error) {
	return unprotectInternal(r, w, outPath, opts)
}

// FinalizeRestoration handles the post-decryption steps: decompression and archive extraction.
func FinalizeRestoration(pr io.Reader, w io.Writer, flags byte, outPath string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	decReader := pr
	if flags&FlagCompress != 0 {
		logger.Info("decompressing zstd stream")
		zr, err := zstd.NewReader(pr)
		if err != nil {
			return fmt.Errorf("failed to initialize zstd reader: %w", err)
		}
		defer zr.Close()
		decReader = zr
	}

	if flags&FlagArchive != 0 {
		logger.Info("extracting tar archive", "target", outPath)
		if err := ExtractArchive(decReader, outPath); err != nil {
			return fmt.Errorf("failed to extract archive: %w", err)
		}
		return nil
	}

	var out io.Writer
	if w != nil {
		out = w
	} else if outPath == "-" {
		out = os.Stdout
	} else {
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return err
		}
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	if _, err := io.Copy(out, decReader); err != nil {
		return fmt.Errorf("failed to write restored data: %w", err)
	}
	return nil
}

func wrapWithArchiver(inputName string, logger *slog.Logger) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		var walkErr error
		defer func() {
			_ = pw.CloseWithError(walkErr)
		}()

		tw := tar.NewWriter(pw)
		defer func() { _ = tw.Close() }()

		baseDir := filepath.Dir(filepath.Clean(inputName))
		walkErr = filepath.Walk(inputName, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(baseDir, path)
			if err != nil {
				return err
			}
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			header.Name = rel
			if err := tw.WriteHeader(header); err != nil {
				return err
			}
			if !info.IsDir() {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				_, err = io.Copy(tw, f)
				return err
			}
			return nil
		})
	}()
	return pr
}

func wrapWithCompressor(r io.Reader, logger *slog.Logger) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		var zErr error
		defer func() {
			_ = pw.CloseWithError(zErr)
		}()
		zw, _ := zstd.NewWriter(pw)
		defer func() { _ = zw.Close() }()
		_, zErr = io.Copy(zw, r)
	}()
	return pr
}

// ExtractArchive takes a decrypted tar stream and extracts it to the target directory.
func ExtractArchive(r io.Reader, outputDir string) error {
	absOutputDir, err := filepath.Abs(outputDir)
	if err != nil {
		return fmt.Errorf("invalid output directory: %w", err)
	}

	if outputDir != "" {
		if err := os.MkdirAll(absOutputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		target := filepath.Join(absOutputDir, h.Name)
		rel, err := filepath.Rel(absOutputDir, target)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("illegal file path in archive: %s", h.Name)
		}

		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("failed to create directory in archive: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory for file: %w", err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(h.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file in archive: %w", err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return fmt.Errorf("failed to copy file data from archive: %w", err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("failed to close file in archive: %w", err)
			}
		}
	}
	return nil
}

func Sha256Sum(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
