package crypto

import (
	"fmt"
	"io"
	"os"
)

// --- Engine Wrappers ---

func (e *Engine) FragmentFile(ctx *EngineContext, inputPath string, opts FragmentOptions) error {
	return e.Crypto.FragmentFile(ctx, inputPath, opts)
}

func (e *Engine) ReassembleFragments(srcDir string, w io.Writer, authorizedPubKey []byte) error {
	return e.Crypto.ReassembleFragments(srcDir, w, authorizedPubKey)
}

func (e *Engine) ReassembleToPath(ctx *EngineContext, srcDir, outputPath string, authorizedPubKey []byte) error {
	return e.Crypto.ReassembleToPath(ctx, srcDir, outputPath, authorizedPubKey)
}

// --- CryptoService Implementation ---

func (s *CryptoService) FragmentFile(_ *EngineContext, inputPath string, opts FragmentOptions) error {
	fi, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("cannot stat input: %w", err)
	}

	opts.OriginalSize = fi.Size()
	if opts.OriginalName == "" {
		opts.OriginalName = fi.Name()
	}
	if opts.OriginalHash == "" {
		hash, err := HashFile(inputPath)
		if err != nil {
			return fmt.Errorf("hashing input: %w", err)
		}
		opts.OriginalHash = hash
	}

	f, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	fw, err := NewFragmentWriter(opts)
	if err != nil {
		return err
	}
	if _, err := io.Copy(fw, f); err != nil {
		_ = fw.Close()
		return err
	}
	return fw.Close()
}

func (s *CryptoService) ReassembleFragments(srcDir string, w io.Writer, authorizedPubKey []byte) error {
	return ReassembleFragments(srcDir, w, authorizedPubKey)
}

func (s *CryptoService) ReassembleToPath(_ *EngineContext, srcDir, outputPath string, authorizedPubKey []byte) error {
	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("cannot create output: %w", err)
	}
	defer out.Close()
	return ReassembleFragments(srcDir, out, authorizedPubKey)
}
