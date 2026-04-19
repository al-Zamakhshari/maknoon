package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// MaknoonDir is the default directory name for Maknoon data.
	MaknoonDir = ".maknoon"
	// KeysDir is the subdirectory for storing keys.
	KeysDir = "keys"
	// VaultsDir is the subdirectory for storing vaults.
	VaultsDir = "vaults"
	// ProfilesDir is the subdirectory for custom profiles.
	ProfilesDir = "profiles"
)

// IdentityManager handles resolution and discovery of cryptographic identities.
type IdentityManager struct {
	KeysDir  string
	HomeDir  string
}

// NewIdentityManager creates a new manager with default paths.
func NewIdentityManager() *IdentityManager {
	home, _ := os.UserHomeDir()
	return &IdentityManager{
		KeysDir: filepath.Join(home, MaknoonDir, KeysDir),
		HomeDir: home,
	}
}

// ResolveKeyPath checks if a key exists locally, in the manager's keys directory, or in environment variables.
func (m *IdentityManager) ResolveKeyPath(path string, envVar string) string {
	// 1. Check if provided path is actually a path to a file
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		// 2. Check in managed keys directory
		maknoonPath := filepath.Join(m.KeysDir, path)
		if _, err := os.Stat(maknoonPath); err == nil {
			return maknoonPath
		}
	}

	// 3. If path is empty or not found, check environment variable
	if envVar != "" {
		if env := os.Getenv(envVar); env != "" {
			if _, err := os.Stat(env); err == nil {
				return env
			}
		}
	}

	return path // Fallback
}

// ListActiveIdentities returns absolute paths to all available public keys.
func (m *IdentityManager) ListActiveIdentities() ([]string, error) {
	var keys []string
	if _, err := os.Stat(m.KeysDir); os.IsNotExist(err) {
		return keys, nil
	}

	files, err := os.ReadDir(m.KeysDir)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".pub") {
			keys = append(keys, filepath.Join(m.KeysDir, f.Name()))
		}
	}
	return keys, nil
}

// ResolveKeyPath checks if a key exists locally, in ~/.maknoon/keys/, or in environment variables.
func ResolveKeyPath(path string, envVar string) string {
	return NewIdentityManager().ResolveKeyPath(path, envVar)
}

// GetDefaultVaultPath returns the path to the default vault file.
func GetDefaultVaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, MaknoonDir, VaultsDir, "default.db")
}

// EnsureMaknoonDirs creates the necessary directory structure for keys, vaults, and profiles.
func EnsureMaknoonDirs() error {
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, MaknoonDir)

	dirs := []string{
		filepath.Join(base, KeysDir),
		filepath.Join(base, VaultsDir),
		filepath.Join(base, ProfilesDir),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return nil
}

// ValidatePath ensures a path is safe to use.
// If restricted is true, it limits file operations to the user's home and system temp directories.
func ValidatePath(path string, restricted bool) error {
	if path == "-" || path == "" {
		return nil
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	// Always resolve symlinks for final validation.
	// If the file doesn't exist, resolve symlinks of the parent directory.
	evalPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		parentEval, err2 := filepath.EvalSymlinks(filepath.Dir(absPath))
		if err2 == nil {
			evalPath = filepath.Join(parentEval, filepath.Base(absPath))
		} else {
			evalPath = absPath
		}
	}

	if restricted {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		evalHome, _ := filepath.EvalSymlinks(home)

		tmp := os.TempDir()
		evalTmp, _ := filepath.EvalSymlinks(tmp)

		// Ensure the path is within the home directory or system temp directory
		if !strings.HasPrefix(evalPath, evalHome) && !strings.HasPrefix(evalPath, evalTmp) {
			return fmt.Errorf("security policy: arbitrary file paths outside home or temp are prohibited")
		}
	}

	return nil
}
