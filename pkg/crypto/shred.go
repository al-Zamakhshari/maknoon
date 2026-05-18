package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
)

// SecureDelete securely wipes and removes a file or directory.
func (e *Engine) SecureDeleteStream(path string) error {
	// Clean the path to remove any traversal sequences before touching the filesystem.
	safe := filepath.Clean(path)
	e.Logger.Debug("securely deleting path", "path", safe)
	info, err := os.Stat(safe)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return e.shredDirectory(safe)
	}
	return e.shredFile(safe)
}

func (e *Engine) shredFile(path string) error {
	safe := filepath.Clean(path)
	e.Logger.Debug("shredding file", "path", safe)
	// Open file for writing only
	f, err := os.OpenFile(safe, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}

	size := info.Size()
	if size > 0 {
		// Single pass wipe with zeros.
		// While multiple passes with random data were standard for HDDs,
		// a single pass is generally sufficient for modern flash controllers
		// to mark blocks for garbage collection or just clear the logical mapping.
		//
		// IMPORTANT — SSD wear-leveling limitation: On SSDs and NVMe drives, the
		// Flash Translation Layer (FTL) maps logical block addresses to physical NAND
		// cells. When a block is overwritten, the FTL may write the new data to a
		// *different* physical cell and mark the old cell for deferred erasure. This
		// means the original data may remain physically present on the NAND until the
		// garbage collector reclaims it — potentially days or weeks later.
		// This overwrite operation provides logical-layer hygiene only.
		// For true data destruction guarantees, use Full Disk Encryption (FDE) so
		// that physically recovered data is still ciphertext without the disk key.
		zeros := make([]byte, 64*1024) // 64KB buffer
		for written := int64(0); written < size; {
			todo := size - written
			if todo > int64(len(zeros)) {
				todo = int64(len(zeros))
			}
			n, err := f.Write(zeros[:todo])
			if err != nil {
				_ = f.Close()
				return err
			}
			written += int64(n)
		}
	}

	// Flush to disk
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	// Rename to a random string to obscure original filename in metadata
	randomName := make([]byte, 16)
	finalPath := safe
	if _, err := io.ReadFull(rand.Reader, randomName); err == nil {
		newName := filepath.Join(filepath.Dir(safe), hex.EncodeToString(randomName))
		if err := os.Rename(safe, newName); err == nil {
			finalPath = newName
		}
	}

	// Finally, remove the file
	return os.Remove(finalPath)
}

func (e *Engine) shredDirectory(path string) error {
	safe := filepath.Clean(path)
	e.Logger.Debug("shredding directory", "path", safe)
	entries, err := os.ReadDir(safe)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		fullPath := filepath.Join(safe, entry.Name())
		if entry.IsDir() {
			if err := e.shredDirectory(fullPath); err != nil {
				return err
			}
		} else {
			if err := e.shredFile(fullPath); err != nil {
				return err
			}
		}
	}

	// Remove the now-empty directory
	return os.Remove(safe)
}
