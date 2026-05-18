package crypto

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultOperations(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "maknoon-vault-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := DefaultConfig()
	cfg.Paths.VaultsDir = tempDir
	cfg.Paths.KeysDir = filepath.Join(tempDir, "keys")
	_ = os.MkdirAll(cfg.Paths.KeysDir, 0700)

	vaultStore := &FileSystemVaultStore{BaseDir: cfg.Paths.VaultsDir}
	policy := &HumanPolicy{}
	logger := slog.Default()

	engine, err := NewEngine(policy, nil, cfg, vaultStore, logger)
	require.NoError(t, err)
	defer engine.Close()

	ctx := context.Background()
	ectx := &EngineContext{Context: ctx, Policy: policy}

	vaultName := "testvault"
	passphrase := "master-pass"
	service := "github"
	username := "alice"
	password := "secret"

	t.Run("VaultSet", func(t *testing.T) {
		entry := &VaultEntry{
			Service:  service,
			Username: username,
			Password: SecretBytes(password),
		}
		err := engine.VaultSet(ectx, vaultName, entry, []byte(passphrase), "", true)
		assert.NoError(t, err)
	})

	t.Run("VaultGet", func(t *testing.T) {
		res, err := engine.VaultGet(ectx, vaultName, service, []byte(passphrase), "")
		require.NoError(t, err)
		assert.Equal(t, username, res.Username)
		assert.Equal(t, password, string(res.Password))
	})

	t.Run("VaultList", func(t *testing.T) {
		entries, err := engine.VaultList(ectx, vaultName, []byte(passphrase))
		require.NoError(t, err)
		found := false
		for _, e := range entries {
			if e.Service == service {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("VaultRename", func(t *testing.T) {
		newVaultName := "newtestvault"
		err := engine.VaultRename(ectx, vaultName, newVaultName)
		assert.NoError(t, err)

		// Verify old is gone, new is there
		res, err := engine.VaultGet(ectx, newVaultName, service, []byte(passphrase), "")
		require.NoError(t, err)
		assert.Equal(t, username, res.Username)
	})

	t.Run("VaultDelete", func(t *testing.T) {
		err := engine.VaultDelete(ectx, "newtestvault")
		assert.NoError(t, err)

		_, err = engine.VaultGet(ectx, "newtestvault", service, []byte(passphrase), "")
		assert.Error(t, err)
	})
}

func TestBadgerVaultOperations(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "maknoon-badger-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := DefaultConfig()
	cfg.Paths.VaultsDir = tempDir

	vaultStore := &FileSystemVaultStore{BaseDir: cfg.Paths.VaultsDir, Backend: "badger"}
	policy := &HumanPolicy{}
	logger := slog.Default()

	engine, err := NewEngine(policy, nil, cfg, vaultStore, logger)
	require.NoError(t, err)
	defer engine.Close()

	ctx := context.Background()
	ectx := &EngineContext{Context: ctx, Policy: policy}

	vaultName := "badgervault"
	passphrase := "master-pass"
	entry := &VaultEntry{
		Service:  "svc",
		Username: "user",
		Password: SecretBytes("pass"),
	}

	err = engine.VaultSet(ectx, vaultName, entry, []byte(passphrase), "", true)
	assert.NoError(t, err)

	res, err := engine.VaultGet(ectx, vaultName, "svc", []byte(passphrase), "")
	require.NoError(t, err)
	assert.Equal(t, "user", res.Username)
}

func TestVaultBlob(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "maknoon-blob-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := DefaultConfig()
	cfg.Paths.VaultsDir = tempDir

	engine, err := NewEngine(&HumanPolicy{}, nil, cfg, nil, nil)
	require.NoError(t, err)
	defer engine.Close()

	ectx := &EngineContext{Policy: &HumanPolicy{}}
	vault := "blobvault"
	pass := []byte("pass")
	key := "agent_memory_key"
	blobData := "some complex agent state or encrypted context"

	entry := &VaultEntry{
		Service: key,
		Blob:    SecretBytes(blobData),
	}

	err = engine.VaultSet(ectx, vault, entry, pass, "", true)
	require.NoError(t, err)

	entryRetrieved, err := engine.VaultGet(ectx, vault, key, pass, "")
	require.NoError(t, err)
	assert.Equal(t, blobData, string(entryRetrieved.Blob))
	assert.Empty(t, entryRetrieved.Password)
}

// TestConcurrentVaultAccess verifies that 10 goroutines can simultaneously set
// and get different services in the same vault without data races or corruption.
func TestConcurrentVaultAccess(t *testing.T) {
	tempDir := t.TempDir()
	cfg := DefaultConfig()
	cfg.Paths.VaultsDir = tempDir

	engine, err := NewEngine(&HumanPolicy{}, nil, cfg, nil, slog.Default())
	require.NoError(t, err)
	defer engine.Close()

	vaultPath := filepath.Join(tempDir, "concurrent.vault")
	passphrase := []byte("concurrent-test-pass")
	ectx := &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}

	const workers = 10
	var wg sync.WaitGroup
	errs := make(chan error, workers*2)

	// Phase 1: all workers set their own service entry
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			entry := &VaultEntry{
				Service:  fmt.Sprintf("svc-%d", n),
				Password: SecretBytes(fmt.Sprintf("pass-%d", n)),
			}
			if err := engine.VaultSet(ectx, vaultPath, entry, passphrase, "", false); err != nil {
				errs <- fmt.Errorf("worker %d set: %w", n, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// Phase 2: verify each entry is readable and correct
	errs2 := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			got, err := engine.VaultGet(ectx, vaultPath, fmt.Sprintf("svc-%d", n), passphrase, "")
			if err != nil {
				errs2 <- fmt.Errorf("worker %d get: %w", n, err)
				return
			}
			expected := fmt.Sprintf("pass-%d", n)
			if string(got.Password) != expected {
				errs2 <- fmt.Errorf("worker %d: expected %q, got %q", n, expected, got.Password)
			}
		}(i)
	}
	wg.Wait()
	close(errs2)
	for err := range errs2 {
		t.Error(err)
	}
}
