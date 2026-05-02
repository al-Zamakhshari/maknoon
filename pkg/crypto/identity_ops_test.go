package crypto

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityOperations(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "maknoon-identity-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := DefaultConfig()
	cfg.Paths.KeysDir = filepath.Join(tempDir, "keys")
	_ = os.MkdirAll(cfg.Paths.KeysDir, 0700)

	keyStore := &FileSystemKeyStore{BaseDir: cfg.Paths.KeysDir}
	idMgr := NewCustomIdentityManager(keyStore, nil)
	idMgr.Config = cfg

	policy := &HumanPolicy{}
	engine, err := NewEngine(policy, idMgr, cfg, nil, nil)
	require.NoError(t, err)
	defer engine.Close()

	ctx := context.Background()
	ectx := &EngineContext{Context: ctx, Policy: policy}

	identityName := "test-id"
	passphrase := "passphrase"

	t.Run("CreateIdentity", func(t *testing.T) {
		res, err := engine.CreateIdentity(ectx, identityName, []byte(passphrase), "", false, "nist")
		require.NoError(t, err)
		assert.Equal(t, identityName, res.BaseName)

		// Verify files exist
		assert.FileExists(t, filepath.Join(cfg.Paths.KeysDir, identityName+".kem.pub"))
		assert.FileExists(t, filepath.Join(cfg.Paths.KeysDir, identityName+".kem.key"))
	})

	t.Run("IdentityActive", func(t *testing.T) {
		ids, err := engine.IdentityActive(ectx)
		require.NoError(t, err)
		assert.Contains(t, ids, identityName)
	})

	t.Run("IdentityInfo", func(t *testing.T) {
		info, err := engine.IdentityInfo(ectx, identityName)
		require.NoError(t, err)
		assert.Equal(t, identityName, info.Name)
		assert.NotEmpty(t, info.KEMPub)
		assert.NotEmpty(t, info.SIGPub)
	})

	t.Run("IdentityRename", func(t *testing.T) {
		newName := "renamed-id"
		err := engine.IdentityRename(ectx, identityName, newName)
		assert.NoError(t, err)

		ids, _ := engine.IdentityActive(ectx)
		assert.Contains(t, ids, newName)
		assert.NotContains(t, ids, identityName)

		identityName = newName
	})

	t.Run("IdentitySplitAndCombine", func(t *testing.T) {
		mnemonics, err := engine.IdentitySplit(ectx, identityName, 2, 3, passphrase)
		require.NoError(t, err)
		assert.Len(t, mnemonics, 3)

		// Combine
		combinedName := "combined-id"
		res, err := engine.IdentityCombine(ectx, mnemonics[:2], combinedName, "new-pass", false)
		require.NoError(t, err)
		assert.Contains(t, res, combinedName)

		ids, _ := engine.IdentityActive(ectx)
		assert.Contains(t, ids, combinedName)
	})
}
