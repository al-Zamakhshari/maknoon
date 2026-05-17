package crypto

import (
	"os"
	"path/filepath"
	"strings"
)

// --- Engine Wrappers ---

func (e *Engine) WorkspaceCreate(ectx *EngineContext, name string) (string, error) {
	return e.Workspace.Create(ectx, name)
}

func (e *Engine) WorkspaceShred(ectx *EngineContext, path string) error {
	return e.Workspace.Shred(ectx, path)
}

// --- WorkspaceService Implementation ---

// Create creates a temporary, isolated directory for sensitive data processing.
// On Linux, it attempts to use /dev/shm for RAM-disk based security.
func (s *WorkspaceService) Create(ectx *EngineContext, name string) (string, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapVaultWrite); err != nil {
		return "", err
	}

	tempDir := os.TempDir()
	// Check for RAM-disk availability on Linux
	if _, err := os.Stat("/dev/shm"); err == nil {
		tempDir = "/dev/shm"
	}

	// Use a secure naming pattern
	path := filepath.Join(tempDir, "maknoon_workspace_"+name)
	if err := os.MkdirAll(path, 0700); err != nil {
		return "", err
	}

	s.engine.Logger.Info("Created ephemeral workspace", "path", path)
	return path, nil
}

// Shred securely deletes an ephemeral workspace using the engine's secure delete primitives.
func (s *WorkspaceService) Shred(ectx *EngineContext, path string) error {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapVaultWrite); err != nil {
		return err
	}

	// Safety check: only allow shredding directories created by Maknoon
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "maknoon_workspace_") {
		return &ErrPolicyViolation{
			Reason:     "only ephemeral maknoon workspaces can be shredded via this tool",
			PolicyName: ectx.Policy.Name(),
		}
	}

	s.engine.Logger.Info("Shredding ephemeral workspace", "path", path)
	return s.engine.SecureDelete(path)
}
