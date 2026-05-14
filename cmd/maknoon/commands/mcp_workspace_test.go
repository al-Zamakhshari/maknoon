package commands

import (
	"context"
	"os"
	"testing"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
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

	// 1. Store Blob (simulating mcp tool)
	entry := &crypto.VaultEntry{
		Service:  key,
		Blob:     crypto.SecretBytes(data),
		Username: "agent_memory",
	}
	err := GlobalContext.Engine.VaultSet(nil, vault, entry, []byte("mcp-blob-pass"), "", true)
	require.NoError(t, err)

	// 2. Retrieve Blob
	res, err := GlobalContext.Engine.VaultGet(nil, vault, key, []byte("mcp-blob-pass"), "")
	require.NoError(t, err)
	assert.Equal(t, data, string(res.Blob))
}

func TestTunnelResilienceMetrics(t *testing.T) {
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

	// 1. Start Listener
	ln, err := GlobalContext.Engine.TunnelListen(ectx, "127.0.0.1:0", "yamux", "")
	require.NoError(t, err)
	require.NotEmpty(t, ln.Addrs)
	addr := ln.Addrs[0]

	// 2. Start Resilient Tunnel
	opts := tunnel.TunnelOptions{
		RemoteEndpoint: addr,
		UseYamux:       true,
		DataLanes:      2,
		ParityLanes:    1,
		LocalProxyPort: 0,
		Insecure:       true,
	}

	status, err := GlobalContext.Engine.TunnelStart(ectx, opts)
	require.NoError(t, err)
	assert.True(t, status.Active)
	assert.Equal(t, 2, status.DataLanes)
	assert.Equal(t, 1, status.ParityLanes)
	assert.Equal(t, 3, status.HealthyLanes)

	// 3. Verify via NetworkStatus (used by mcp network_status)
	netStatus, err := GlobalContext.Engine.NetworkStatus(ectx)
	require.NoError(t, err)
	assert.True(t, netStatus.Tunnel.Active)
	assert.Equal(t, 2, netStatus.Tunnel.DataLanes)
	assert.Equal(t, 3, netStatus.Tunnel.HealthyLanes)
}
