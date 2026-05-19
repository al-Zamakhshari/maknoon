package commands

import (
	"context"
	"os"
	"testing"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPWorkspaceTools(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)

	if err := InitEngine(); err != nil {
		t.Fatalf("InitEngine failed: %v", err)
	}
	defer func() {
		if GlobalContext.Engine != nil {
			GlobalContext.Engine.Close()
		}
	}()

	ctx := context.Background()
	ectx := &crypto.EngineContext{Context: ctx}

	// 1. Test Workspace Create
	path, err := GlobalContext.Engine.WorkspaceCreate(ectx, "mcp_session")
	require.NoError(t, err)
	assert.Contains(t, path, "maknoon_workspace_mcp_session")

	// 2. Test Workspace Shred
	err = GlobalContext.Engine.WorkspaceShred(ectx, path)
	require.NoError(t, err)
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}

func TestMCPVaultBlobTools(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)

	if err := InitEngine(); err != nil {
		t.Fatalf("InitEngine failed: %v", err)
	}
	defer func() {
		if GlobalContext.Engine != nil {
			GlobalContext.Engine.Close()
		}
	}()

	viper.Set("passphrase", "mcp-blob-pass")
	vault := "agent_memory"
	key := "agent_context_001"
	data := "this is a very secret agent state"

	entry := &crypto.VaultEntry{
		Service:  key,
		Blob:     crypto.SecretBytes(data),
		Username: "agent_memory",
	}
	err := GlobalContext.Engine.VaultSet(nil, vault, entry, []byte("mcp-blob-pass"), "", true)
	require.NoError(t, err)

	res, err := GlobalContext.Engine.VaultGet(nil, vault, key, []byte("mcp-blob-pass"), "")
	require.NoError(t, err)
	assert.Equal(t, data, string(res.Blob))
}
