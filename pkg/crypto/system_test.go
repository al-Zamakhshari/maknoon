package crypto

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditExport(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "maknoon-audit-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	logFile := filepath.Join(tempDir, "audit.log")
	cfg := DefaultConfig()
	cfg.Audit.Enabled = true
	cfg.Audit.LogFile = logFile

	core, err := NewEngine(&HumanPolicy{}, nil, cfg, nil, nil)
	require.NoError(t, err)
	defer core.Close()

	// Decorate with AuditEngine to log events
	logger, err := NewJSONFileLogger(logFile)
	require.NoError(t, err)
	defer logger.Close()

	ae := &AuditEngine{
		Engine: core,
		Logger: logger,
	}

	ctx := context.Background()
	ectx := &EngineContext{Context: ctx, Policy: &HumanPolicy{}}

	// Generate some events
	entry := &VaultEntry{Service: "test", Username: "user", Password: SecretBytes("pass")}
	_ = ae.VaultSet(ectx, "test.vault", entry, []byte("pass"), "", true)

	// CRITICAL: Close logger to flush buffer before export
	logger.Close()

	// Export
	entries, err := ae.AuditExport(ectx)
	require.NoError(t, err)
	assert.NotEmpty(t, entries)

	found := false
	for _, entry := range entries {
		if entry.Action == "vault_set" {
			found = true
			break
		}
	}
	assert.True(t, found, "Expected vault_set event in audit log")
}

func TestDiagnosticAndNetworkStatus(t *testing.T) {
	cfg := DefaultConfig()
	engine, err := NewEngine(&HumanPolicy{}, nil, cfg, nil, nil)
	require.NoError(t, err)
	defer engine.Close()

	ctx := context.Background()
	ectx := &EngineContext{Context: ctx, Policy: &HumanPolicy{}}

	t.Run("Diagnostic", func(t *testing.T) {
		res := engine.Diagnostic()
		assert.NotEmpty(t, res.Timestamp)
		assert.NotEmpty(t, res.System.OS)
	})

	t.Run("NetworkStatus", func(t *testing.T) {
		res, err := engine.NetworkStatus(ectx)
		require.NoError(t, err)
		assert.False(t, res.Tunnel.Active)
	})
}
