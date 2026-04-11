package crypto

import (
	"os"
	"path/filepath"
)

const (
	// MaknoonDir is the default directory name for Maknoon data.
	MaknoonDir = ".maknoon"
	// KeysDir is the subdirectory for storing keys.
	KeysDir = "keys"
	// VaultsDir is the subdirectory for storing vaults.
	VaultsDir = "vaults"
)

// ResolveKeyPath checks if a key exists locally, and if not, looks in ~/.maknoon/keys/
func ResolveKeyPath(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	// Check in ~/.maknoon/keys/
	home, _ := os.UserHomeDir()
	maknoonPath := filepath.Join(home, MaknoonDir, KeysDir, path)
	if _, err := os.Stat(maknoonPath); err == nil {
		return maknoonPath
	}
	return path // Fallback to original
}

// GetDefaultVaultPath returns the path to the default vault file.
func GetDefaultVaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, MaknoonDir, VaultsDir, "default.db")
}

// EnsureMaknoonDirs creates the necessary directory structure for keys and vaults.
func EnsureMaknoonDirs() error {
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, MaknoonDir)

	dirs := []string{
		filepath.Join(base, KeysDir),
		filepath.Join(base, VaultsDir),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return nil
}
