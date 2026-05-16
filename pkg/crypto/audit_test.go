package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type MockAuditLogger struct {
	LastAction   string
	LastMetadata map[string]any
	LastErr      error
}

func (m *MockAuditLogger) LogEvent(action string, metadata map[string]any, err error) {
	m.LastAction = action
	m.LastMetadata = metadata
	m.LastErr = err
}

func (m *MockAuditLogger) SetSigningKey(key []byte) {}

func (m *MockAuditLogger) Close() error { return nil }

func TestAuditEngineDecorator(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	conf := DefaultConfig()
	core, err := NewEngine(&HumanPolicy{}, nil, conf, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer core.Close()

	mockLogger := &MockAuditLogger{}
	ae := &AuditEngine{
		BaseEngine: BaseEngine{Engine: core},
		Logger:     mockLogger,
	}

	t.Run("ProtectLogging", func(t *testing.T) {
		r := bytes.NewReader([]byte("audit-test-data"))
		var w bytes.Buffer
		opts := Options{Passphrase: []byte("pass")}

		_, err := ae.Protect(nil, "audit.txt", r, &w, opts)
		if err != nil {
			t.Fatalf("Protect failed: %v", err)
		}

		if mockLogger.LastAction != "protect" {
			t.Errorf("expected action 'protect', got %s", mockLogger.LastAction)
		}
		if mockLogger.LastMetadata["input"] != "audit.txt" {
			t.Errorf("expected input 'audit.txt', got %v", mockLogger.LastMetadata["input"])
		}
	})

	t.Run("VaultLogging", func(t *testing.T) {
		// Test vault delegation and logging
		ae.VaultGet(nil, "test.vault", "service", []byte("pass"), "")
		if mockLogger.LastAction != "vault_get" {
			t.Errorf("expected action 'vault_get', got %s", mockLogger.LastAction)
		}
	})

	t.Run("JSONFileLogger", func(t *testing.T) {
		tmpLog := filepath.Join(t.TempDir(), "test_audit_perm.log")

		logger, err := NewJSONFileLogger(tmpLog)
		if err != nil {
			t.Fatalf("failed to create logger: %v", err)
		}

		ae.Logger = logger
		ae.VaultGet(nil, "test.vault", "myservice", []byte("pass"), "")
		ae.VaultList(nil, "test.vault", []byte("pass"))
		logger.Close()

		data, err := os.ReadFile(tmpLog)
		if err != nil {
			t.Fatalf("failed to read log: %v", err)
		}

		lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
		if len(lines) < 2 {
			t.Fatalf("expected at least 2 log lines, got %d", len(lines))
		}

		var entry1, entry2 AuditEntry
		json.Unmarshal(lines[0], &entry1)
		json.Unmarshal(lines[1], &entry2)

		if entry2.PrevHash == "" {
			t.Errorf("second entry has empty PrevHash")
		}

		// Calculate expected hash of first entry
		h := sha256.New()
		h.Write(lines[0])
		expectedHash := hex.EncodeToString(h.Sum(nil))

		if entry2.PrevHash != expectedHash {
			t.Errorf("hash mismatch: expected %s, got %s", expectedHash, entry2.PrevHash)
		}
	})
}
