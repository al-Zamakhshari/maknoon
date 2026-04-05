package crypto

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
)

// Options defines settings for the protection process.
type Options struct {
	Passphrase []byte
	PublicKey  []byte
	Compress   bool
	IsArchive  bool
}

// Protect handles the full encryption pipeline for a file or directory.
func Protect(inputPath string, w io.Writer, opts Options) error {
	var sourceReader io.Reader
	var flags byte

	if opts.IsArchive {
		flags |= FlagArchive
		pr, pw := io.Pipe()
		sourceReader = pr
		go func() {
			tw := tar.NewWriter(pw)
			baseDir := filepath.Dir(filepath.Clean(inputPath))
			err := filepath.Walk(inputPath, func(path string, info os.FileInfo, err error) error {
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
	} else {
		f, err := os.Open(inputPath)
		if err != nil {
			return err
		}
		defer f.Close()
		sourceReader = f
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
		return EncryptStreamWithPublicKey(sourceReader, w, opts.PublicKey, flags)
	}
	return EncryptStream(sourceReader, w, opts.Passphrase, flags)
}

// ExtractArchive takes a decrypted tar stream and extracts it to the target directory.
func ExtractArchive(r io.Reader, outputDir string) error {
	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
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
		target := h.Name
		if outputDir != "" {
			target = filepath.Join(outputDir, h.Name)
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
