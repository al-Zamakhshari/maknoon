package crypto

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkspaceLifecycle(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "maknoon-workspace-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := DefaultConfig()
	cfg.Paths.VaultsDir = tempDir
	cfg.Paths.KeysDir = filepath.Join(tempDir, "keys")
	_ = os.MkdirAll(cfg.Paths.KeysDir, 0700)

	engine, err := NewEngine(&HumanPolicy{}, nil, cfg, nil, nil)
	require.NoError(t, err)
	defer engine.Close()

	ectx := &EngineContext{Policy: &HumanPolicy{}}

	// 1. Create Workspace
	path, err := engine.WorkspaceCreate(ectx, "test_session")
	require.NoError(t, err)
	assert.Contains(t, path, "maknoon_workspace_test_session")

	// Verify directory exists and has 0700 permissions
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm())

	// 2. Write a dummy file
	dummyFile := filepath.Join(path, "sensitive.txt")
	err = os.WriteFile(dummyFile, []byte("sensitive data"), 0600)
	require.NoError(t, err)

	// 3. Shred Workspace
	err = engine.WorkspaceShred(ectx, path)
	require.NoError(t, err)

	// Verify directory and file are gone
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestWorkspaceShredSafety(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "maknoon-workspace-safety-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := DefaultConfig()
	cfg.Paths.VaultsDir = tempDir

	engine, err := NewEngine(&HumanPolicy{}, nil, cfg, nil, nil)
	require.NoError(t, err)
	defer engine.Close()

	ectx := &EngineContext{Policy: &HumanPolicy{}}

	// Attempt to shred a path that doesn't follow the maknoon_workspace_ pattern
	badPath := t.TempDir()
	err = engine.WorkspaceShred(ectx, badPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only ephemeral maknoon workspaces can be shredded")
}
