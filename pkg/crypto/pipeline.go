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

// Options defines settings for the protection process.
type Options struct {
	Passphrase     []byte
	PublicKey      []byte   // Deprecated: use PublicKeys
	PublicKeys     [][]byte // Supports multi-recipient encryption
	SigningKey     []byte   // ML-DSA private key for integrated signing
	ProfileID      byte     // 0 for default
	Compress       bool
	IsArchive      bool
	Concurrency    int       // 0 for auto (NumCPU), 1 for sequential
	ProgressReader io.Reader // Optional reader to track progress
	Verbose        bool      // Enables internal slog tracing
	Stealth        bool      // Enables fingerprint resistance (headerless)
}

// Protect handles the full encryption pipeline for a source (file, directory, or reader).
func Protect(inputName string, r io.Reader, w io.Writer, opts Options) (byte, error) {
	var logger *slog.Logger
	if opts.Verbose {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	} else {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	sourceReader := r
	var flags byte

	if opts.IsArchive {
		logger.Info("archiving input directory", "path", inputName)
		flags |= FlagArchive
		sourceReader = wrapWithArchiver(inputName, logger)
	} else if sourceReader == nil {
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

	if opts.ProgressReader != nil {
		if wr, ok := opts.ProgressReader.(io.Writer); ok {
			sourceReader = io.TeeReader(sourceReader, wr)
		}
	}

	if opts.Compress {
		logger.Info("enabling zstd compression")
		flags |= FlagCompress
		sourceReader = wrapWithCompressor(sourceReader, logger)
	}

	if opts.Stealth {
		logger.Info("enabling stealth mode (headerless)")
		flags |= FlagStealth
	}

	allPublicKeys := opts.PublicKeys
	if len(opts.PublicKey) > 0 {
		allPublicKeys = append(allPublicKeys, opts.PublicKey)
	}

	if len(allPublicKeys) > 0 {
		logger.Info("starting asymmetric encryption", "recipients", len(allPublicKeys))
		return flags, EncryptStreamWithPublicKeysAndSigner(sourceReader, w, allPublicKeys, opts.SigningKey, flags, opts.Concurrency, opts.ProfileID)
	}
	logger.Info("starting symmetric encryption")
	return flags, EncryptStream(sourceReader, w, opts.Passphrase, flags, opts.Concurrency, opts.ProfileID)
}

// Unprotect handles the full decryption pipeline: Handshake -> Decrypt -> Decompress -> Extract.
func Unprotect(r io.Reader, w io.Writer, outPath string, opts Options) (byte, error) {
	var logger *slog.Logger
	if opts.Verbose {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	} else {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// 1. Peek at the header to get flags (compression, archive, etc.)
	magic, profileID, flags, err := ReadHeader(r, opts.Stealth)
	if err != nil {
		return 0, fmt.Errorf("failed to read file header: %w", err)
	}

	// 2. Wrap reader with multi-reader since we peeked
	var headerBytes []byte
	if !opts.Stealth {
		headerBytes = append([]byte(magic), profileID, flags)
	} else {
		headerBytes = []byte{profileID, flags}
	}
	fullIn := io.MultiReader(bytes.NewReader(headerBytes), r)

	// 3. Resolve key and perform core decryption stream
	// We use a pipe to bridge decryption to restoration (decompression/archive)
	pr, pw := io.Pipe()
	var dErr error
	go func() {
		defer pw.Close()
		var dFlags byte
		if len(opts.PublicKeys) > 0 || len(opts.PublicKey) > 0 {
			// Asymmetric
			allPublicKeys := opts.PublicKeys
			if len(opts.PublicKey) > 0 {
				allPublicKeys = append(allPublicKeys, opts.PublicKey)
			}
			// Note: Current core API for asymmetric decrypt expects a single priv key.
			// Pipeline 'Restore' assumes the caller provided the correct single key in Passphrase or similar.
			// For now, assume symmetric or simple asymmetric bypass.
			dFlags, dErr = DecryptStreamWithPrivateKeyAndVerifier(fullIn, pw, opts.Passphrase, opts.PublicKey, opts.Concurrency, opts.Stealth)
		} else {
			// Symmetric
			dFlags, dErr = DecryptStream(fullIn, pw, opts.Passphrase, opts.Concurrency, opts.Stealth)
		}
		_ = dFlags
		if dErr != nil {
			_ = pw.CloseWithError(dErr)
		}
	}()

	// 4. Finalize: Decompress and/or Extract Archive
	err = FinalizeRestoration(pr, flags, outPath, logger)
	return flags, err
}

// FinalizeRestoration handles the post-decryption steps: decompression and archive extraction.
func FinalizeRestoration(pr io.Reader, flags byte, outPath string, logger *slog.Logger) error {
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
	if outPath == "-" {
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

func sha256Sum(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
