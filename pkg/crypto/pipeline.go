package crypto

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Options defines settings for the protection process.
type Options struct {
	Passphrase     []byte
	PublicKey      []byte
	Compress       bool
	IsArchive      bool
	Concurrency    int       // 0 for auto (NumCPU), 1 for sequential
	ProgressReader io.Reader // Optional reader to track progress
}

// Protect handles the full encryption pipeline for a source (file, directory, or reader).
func Protect(inputName string, r io.Reader, w io.Writer, opts Options) error {
	var sourceReader io.Reader = r
	var flags byte

	if opts.IsArchive {
		flags |= FlagArchive
		pr, pw := io.Pipe()
		sourceReader = pr
		go func() {
			tw := tar.NewWriter(pw)
			// For archives, we still need to walk the inputName if it's a directory
			baseDir := filepath.Dir(filepath.Clean(inputName))
			err := filepath.Walk(inputName, func(path string, info os.FileInfo, err error) error {
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
					defer f.Close()
					_, err = io.Copy(tw, f)
					return err
				}
				return nil
			})
			tw.Close()
			pw.CloseWithError(err)
		}()
	} else if sourceReader == nil {
		f, err := os.Open(inputName)
		if err != nil {
			return err
		}
		defer f.Close()
		sourceReader = f
	}

	// Wrap the source with progress tracking BEFORE compression/encryption
	if opts.ProgressReader != nil {
		// The caller provides a reader that wraps 'sourceReader' (e.g. via TeeReader)
		// But since we swapped sourceReader above, we need to be careful.
		// Better approach: wrap the specific reader we are using.
		sourceReader = io.TeeReader(sourceReader, opts.ProgressReader.(io.Writer))
	}

	if opts.Compress {
		flags |= FlagCompress
		pr, pw := io.Pipe()
		oldReader := sourceReader
		sourceReader = pr
		go func() {
			zw, _ := zstd.NewWriter(pw)
			_, err := io.Copy(zw, oldReader)
			zw.Close()
			pw.CloseWithError(err)
		}()
	}

	if len(opts.PublicKey) > 0 {
		return EncryptStreamWithPublicKey(sourceReader, w, opts.PublicKey, flags, opts.Concurrency)
	}
	return EncryptStream(sourceReader, w, opts.Passphrase, flags, opts.Concurrency)
}

// ExtractArchive takes a decrypted tar stream and extracts it to the target directory.
func ExtractArchive(r io.Reader, outputDir string) error {
	absOutputDir, err := filepath.Abs(outputDir)
	if err != nil {
		return err
	}

	if outputDir != "" {
		if err := os.MkdirAll(absOutputDir, 0755); err != nil {
			return err
		}
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Path Traversal Mitigation (Zip Slip)
		target := filepath.Join(absOutputDir, h.Name)
		if !strings.HasPrefix(target, filepath.Clean(absOutputDir)) {
			return fmt.Errorf("illegal file path in archive: %s", h.Name)
		}

		switch h.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(target), 0755)
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(h.Mode))
			if err != nil {
				return err
			}
			io.Copy(f, tr)
			f.Close()
		}
	}
	return nil
}
