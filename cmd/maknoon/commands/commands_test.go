// Package commands contains the implementation and tests for the Maknoon CLI commands.
package commands

import (
	"fmt"
	"os"
	"testing"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
)

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "maknoon-cmd-test")
	if err != nil {
		fmt.Printf("Failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)

	_ = InitEngine()
	// Initialize a test UI that allows capturing sensitive output into buffers
	GlobalContext.UI = &UIHandler{
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Interactive: true, // Allow tests to see "sensitive" info
		JSON:        false,
	}

	code := m.Run()

	if GlobalContext.Engine != nil {
		_ = GlobalContext.Engine.Close()
	}

	os.Setenv("HOME", origHome)
	os.Exit(code)
}

func TestResolveKeyPath(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "maknoon_key_*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// 1. Explicit path
	res := crypto.ResolveKeyPath(tmpFile.Name(), "UNUSED")
	if res != tmpFile.Name() {
		t.Errorf("Expected %s, got %s", tmpFile.Name(), res)
	}

	// 2. Env var
	envKey := "MAKNOON_TEST_KEY_PATH"
	if err := os.Setenv(envKey, tmpFile.Name()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Unsetenv(envKey) }()
	res = crypto.ResolveKeyPath("", envKey)
	if res != tmpFile.Name() {
		t.Errorf("Expected %s from env, got %s", tmpFile.Name(), res)
	}
}
