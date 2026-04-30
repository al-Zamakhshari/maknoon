package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigMerging(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	ResetGlobalConfig()

	// 1. Create a config file
	conf := DefaultConfig()
	conf.Performance.Concurrency = 10
	conf.DefaultIdentity = "file-id"
	if err := conf.Save(); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	// 2. Set environment variables
	os.Setenv("MAKNOON_DEFAULT_IDENTITY", "env-id")
	os.Setenv("MAKNOON_PERFORMANCE_CONCURRENCY", "20")
	defer os.Unsetenv("MAKNOON_DEFAULT_IDENTITY")
	defer os.Unsetenv("MAKNOON_PERFORMANCE_CONCURRENCY")

	// 3. Load config and verify merging
	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Env should override File
	if loaded.DefaultIdentity != "env-id" {
		t.Errorf("Expected default_identity 'env-id', got '%s'", loaded.DefaultIdentity)
	}
	if loaded.Performance.Concurrency != 20 {
		t.Errorf("Expected concurrency 20, got %d", loaded.Performance.Concurrency)
	}

	// Non-overridden values should persist from File
	expectedKeysDir := filepath.Join(tmpDir, MaknoonDir, KeysDir)
	if loaded.Paths.KeysDir != expectedKeysDir {
		t.Errorf("Expected keys_dir '%s', got '%s'", expectedKeysDir, loaded.Paths.KeysDir)
	}
}

func TestConfigValidation(t *testing.T) {
	conf := DefaultConfig()

	// Valid config
	if err := conf.Validate(); err != nil {
		t.Errorf("Valid config failed validation: %v", err)
	}

	// Invalid memory
	conf.Security.ArgonMemory = 512
	if err := conf.Validate(); err == nil {
		t.Error("Expected error for low memory, got nil")
	}
	conf.Security.ArgonMemory = 64 * 1024

	// Invalid Nostr URL
	conf.Nostr.Relays = []string{"http://not-ws"}
	if err := conf.Validate(); err == nil {
		t.Error("Expected error for invalid Nostr URL, got nil")
	}
}

func TestEngineUpdateConfigPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	// 1. Human Policy (Allowed)
	engine, _ := NewEngine(&HumanPolicy{}, nil, nil, nil, nil)
	newConf := DefaultConfig()
	newConf.DefaultIdentity = "human-updated"

	if err := engine.UpdateConfig(nil, newConf); err != nil {
		t.Errorf("Human policy should allow config update, got: %v", err)
	}

	// 2. Agent Policy (Denied)
	agentEngine, _ := NewEngine(&AgentPolicy{}, nil, nil, nil, nil)
	if err := agentEngine.UpdateConfig(nil, newConf); err == nil {
		t.Error("Agent policy should deny config update, got nil")
	} else if _, ok := err.(*ErrPolicyViolation); !ok {
		t.Errorf("Expected ErrPolicyViolation, got %T", err)
	}
}

func TestConfigPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	ResetGlobalConfig()
	engine, _ := NewEngine(&HumanPolicy{}, nil, nil, nil, nil)

	// 1. Update config via engine
	conf := engine.GetConfig()
	conf.DefaultIdentity = "persistence-test"
	conf.Performance.Concurrency = 99

	if err := engine.UpdateConfig(nil, conf); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	// 2. Clear cache and reload from disk
	ResetGlobalConfig()
	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.DefaultIdentity != "persistence-test" {
		t.Errorf("Persistence failed for default_identity")
	}
	if loaded.Performance.Concurrency != 99 {
		t.Errorf("Persistence failed for concurrency")
	}

	// 3. Verify file permissions
	path := filepath.Join(tmpDir, MaknoonDir, ConfigFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("Expected config file permission 0600, got %o", info.Mode().Perm())
	}
}
