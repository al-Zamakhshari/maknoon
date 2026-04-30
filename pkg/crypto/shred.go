package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
)

// SecureDelete securely wipes and removes a file or directory.
func (e *Engine) SecureDelete(path string) error {
	e.Logger.Debug("securely deleting path", "path", path)
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return e.shredDirectory(path)
	}
	return e.shredFile(path)
}

func (e *Engine) shredFile(path string) error {
	e.Logger.Debug("shredding file", "path", path)
	// Open file for writing only
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
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
	finalPath := path
	if _, err := io.ReadFull(rand.Reader, randomName); err == nil {
		newName := filepath.Join(filepath.Dir(path), hex.EncodeToString(randomName))
		if err := os.Rename(path, newName); err == nil {
			finalPath = newName
		}
	}

	// Finally, remove the file
	return os.Remove(finalPath)
}

func (e *Engine) shredDirectory(path string) error {
	e.Logger.Debug("shredding directory", "path", path)
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		fullPath := filepath.Join(path, entry.Name())
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
	return os.Remove(path)
}
