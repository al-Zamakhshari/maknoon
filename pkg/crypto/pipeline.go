package crypto

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Options defines settings for the protection process.
type Options struct {
	Passphrase      []byte
	PublicKey       []byte   // Deprecated: use Recipients
	Recipients      [][]byte // Supports multi-recipient encryption
	LocalPrivateKey []byte   // Local KEM private key for decryption
	SigningKey      []byte   // ML-DSA private key for integrated signing
	ProfileID       byte     // 0 for default
	Compress        bool
	IsArchive       bool
	Concurrency     int                // 0 for auto (NumCPU), 1 for sequential
	TotalSize       int64              // Known total size of input for progress tracking
	EventStream     chan<- EngineEvent // Optional channel for telemetry
	ProgressReader  io.Reader          // Deprecated: use EventStream
	Verbose         bool               // Enables internal slog tracing
	Stealth         bool               // Enables fingerprint resistance (headerless)
}

func (o *Options) Emit(ev EngineEvent) {
	if o.EventStream != nil {
		defer func() { _ = recover() }()
		o.EventStream <- ev
	}
}

// Protect handles the full encryption pipeline under the active policy.
func (e *Engine) Protect(ectx *EngineContext, inputName string, r io.Reader, w io.Writer, opts Options) (byte, error) {
	ectx = e.context(ectx)
	// If EventStream is provided in opts but not in ectx, update ectx
	if opts.EventStream != nil && ectx.Events == nil {
		ectx.Events = opts.EventStream
	}

	// 1. Enforce Path Policy
	if inputName != "-" && inputName != "" {
		if err := ectx.Policy.ValidatePath(inputName); err != nil {
			return 0, err
		}
	}

	// 2. Clamp Resources
	opts.Concurrency = ectx.Policy.ClampConcurrency(opts.Concurrency, e.Config.AgentLimits.MaxWorkers)

	return protectInternal(ectx, inputName, r, w, opts)
}

func protectInternal(ectx *EngineContext, inputName string, r io.Reader, w io.Writer, opts Options) (byte, error) {
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

	if len(opts.Passphrase) > 0 {
		logger.Info("starting symmetric encryption")
	} else if len(opts.Recipients) > 0 || len(opts.PublicKey) > 0 {
		logger.Info("starting asymmetric encryption")
	}

	var totalBytes int64
	if inputName != "-" && inputName != "" {
		if fi, err := os.Stat(inputName); err == nil && !fi.IsDir() {
			totalBytes = fi.Size()
		}
	}
	ectx.Emit(EventEncryptionStarted{TotalBytes: totalBytes})

	// 1. Setup Source
	sourceReader := r
	if sourceReader == nil {
		if opts.IsArchive {
			sourceReader = wrapWithArchiver(inputName, logger)
		} else if inputName == "-" {
			sourceReader = os.Stdin
		} else {
			f, err := os.Open(inputName)
			if err != nil {
				return 0, &ErrIO{Path: inputName, Reason: err.Error()}
			}
			defer func() { _ = f.Close() }()
			sourceReader = f
		}
	}

	// 2. Progress Tracking (legacy support)
	if opts.ProgressReader != nil {
		if wr, ok := opts.ProgressReader.(io.Writer); ok {
			sourceReader = io.TeeReader(sourceReader, wr)
		}
	}

	// 3. Compression
	if opts.Compress {
		sourceReader = wrapWithCompressor(sourceReader, logger)
	}

	// 4. Core Encryption
	allPublicKeys := opts.Recipients
	if len(opts.PublicKey) > 0 {
		allPublicKeys = append(allPublicKeys, opts.PublicKey)
	}

	var err error
	if len(allPublicKeys) > 0 {
		err = EncryptStreamWithPublicKeysAndEvents(sourceReader, w, allPublicKeys, opts.SigningKey, flags, opts.Concurrency, opts.ProfileID, ectx)
	} else {
		err = EncryptStreamWithEvents(sourceReader, w, opts.Passphrase, flags, opts.Concurrency, opts.ProfileID, ectx)
	}

	return flags, err
}

// Unprotect handles the full decryption pipeline: Handshake -> Decrypt -> Decompress -> Extract.
func (e *Engine) Unprotect(ectx *EngineContext, r io.Reader, w io.Writer, outPath string, opts Options) (byte, error) {
	ectx = e.context(ectx)
	// If EventStream is provided in opts but not in ectx, update ectx
	if opts.EventStream != nil && ectx.Events == nil {
		ectx.Events = opts.EventStream
	}

	// 1. Enforce Path Policy
	if outPath != "-" && outPath != "" {
		if err := ectx.Policy.ValidatePath(outPath); err != nil {
			return 0, err
		}
	}

	// 2. Clamp Resources
	opts.Concurrency = ectx.Policy.ClampConcurrency(opts.Concurrency, e.Config.AgentLimits.MaxWorkers)

	return unprotectInternal(ectx, r, w, outPath, opts)
}

func unprotectInternal(ectx *EngineContext, r io.Reader, w io.Writer, outPath string, opts Options) (byte, error) {
	var logger *slog.Logger
	if opts.Verbose {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	} else {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	ectx.Emit(EventDecryptionStarted{TotalBytes: opts.TotalSize})

	// 1. Peek at the header to determine flags
	magic, profileID, flags, recipientCount, err := ReadHeader(r, opts.Stealth)
	if err != nil {
		return 0, err
	}

	if magic == MagicHeaderSym {
		logger.Info("handshake complete", "mode", "symmetric")
	} else if magic == MagicHeaderAsym {
		logger.Info("handshake complete", "mode", "asymmetric", "recipients", recipientCount)
	}

	// Reconstruct input for the actual decryption
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

	// 2. Core Decryption (returns decrypted payload via a pipe)
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		var dErr error
		if magic == MagicHeaderAsym || (opts.LocalPrivateKey != nil || opts.PublicKey != nil) {
			_, _, dErr = DecryptStreamWithPrivateKeyAndEvents(fullIn, pw, opts.LocalPrivateKey, opts.PublicKey, opts.Concurrency, opts.Stealth, ectx)
		} else {
			_, _, dErr = DecryptStreamWithEvents(fullIn, pw, opts.Passphrase, opts.Concurrency, opts.Stealth, ectx)
		}

		if dErr != nil {
			_ = pw.CloseWithError(dErr)
		}
	}()

	// 3. Finalize Post-Processing (Decompress -> Extract)
	err = FinalizeRestoration(pr, w, flags, outPath, logger)
	if err != nil {
		return flags, err
	}

	return flags, nil
}

// --- Legacy Shims ---

// Protect handles the full encryption pipeline for a source (file, directory, or reader).
// This is a shim that uses a default HumanPolicy engine.
func Protect(inputName string, r io.Reader, w io.Writer, opts Options) (byte, error) {
	ectx := &EngineContext{
		Context: context.Background(),
		Events:  opts.EventStream,
		Policy:  &HumanPolicy{},
	}
	return protectInternal(ectx, inputName, r, w, opts)
}

// Unprotect handles the full decryption pipeline: Handshake -> Decrypt -> Decompress -> Extract.
// This is a shim that uses a default HumanPolicy engine.
func Unprotect(r io.Reader, w io.Writer, outPath string, opts Options) (byte, error) {
	ectx := &EngineContext{
		Context: context.Background(),
		Events:  opts.EventStream,
		Policy:  &HumanPolicy{},
	}
	return unprotectInternal(ectx, r, w, outPath, opts)
}

// FinalizeRestoration handles the post-decryption steps: decompression and archive extraction.
func FinalizeRestoration(pr io.Reader, w io.Writer, flags byte, outPath string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	var decReader io.Reader = pr
	if flags&FlagCompress != 0 {
		logger.Info("decompressing zstd stream")
		zr, err := zstd.NewReader(pr)
		if err != nil {
			return &ErrCrypto{Reason: fmt.Sprintf("failed to initialize zstd reader: %v", err)}
		}
		defer zr.Close()
		decReader = zr
	}

	if flags&FlagArchive != 0 {
		logger.Info("extracting tar archive", "target", outPath)
		if err := ExtractArchive(decReader, outPath); err != nil {
			return &ErrIO{Path: outPath, Reason: fmt.Sprintf("failed to extract archive: %v", err)}
		}
		return nil
	}

	var out io.Writer
	if w != nil {
		out = w
	} else if outPath == "-" {
		out = os.Stdout
	} else if outPath != "" {
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return &ErrIO{Path: filepath.Dir(outPath), Reason: err.Error()}
		}
		f, err := os.Create(outPath)
		if err != nil {
			return &ErrIO{Path: outPath, Reason: err.Error()}
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	if out != nil {
		if _, err := io.Copy(out, decReader); err != nil {
			return &ErrIO{Path: "output", Reason: err.Error()}
		}
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
		return &ErrIO{Path: outputDir, Reason: "invalid output directory"}
	}

	if outputDir != "" {
		if err := os.MkdirAll(absOutputDir, 0755); err != nil {
			return &ErrIO{Path: absOutputDir, Reason: err.Error()}
		}
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return &ErrFormat{Reason: fmt.Sprintf("failed to read tar header: %v", err)}
		}

		target := filepath.Join(absOutputDir, h.Name)
		rel, err := filepath.Rel(absOutputDir, target)
		if err != nil || strings.HasPrefix(rel, "..") {
			return &ErrPolicyViolation{Reason: "illegal file path in archive", Path: h.Name}
		}

		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return &ErrIO{Path: target, Reason: err.Error()}
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return &ErrIO{Path: filepath.Dir(target), Reason: err.Error()}
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(h.Mode))
			if err != nil {
				return &ErrIO{Path: target, Reason: err.Error()}
			}
			if _, err = io.Copy(f, tr); err != nil {
				_ = f.Close()
				return &ErrIO{Path: target, Reason: err.Error()}
			}
			if err = f.Close(); err != nil {
				return &ErrIO{Path: target, Reason: err.Error()}
			}
		}
	}
	return nil
}

func (e *Engine) FinalizeRestoration(ectx *EngineContext, pr io.Reader, w io.Writer, flags byte, outPath string, logger *slog.Logger) error {
	return FinalizeRestoration(pr, w, flags, outPath, logger)
}

func Sha256Sum(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
