package crypto

import (
	"bytes"
	"os"
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

func (m *MockAuditLogger) Close() error { return nil }

func TestAuditEngineDecorator(t *testing.T) {
	core, _ := NewEngine(&HumanPolicy{}, nil, nil, nil, nil)
	mockLogger := &MockAuditLogger{}
	ae := &AuditEngine{
		Engine: core,
		Logger: mockLogger,
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
		tmpLog := "test_audit_perm.log"
		defer os.Remove(tmpLog)

		logger, err := NewJSONFileLogger(tmpLog)
		if err != nil {
			t.Fatalf("failed to create logger: %v", err)
		}

		ae.Logger = logger
		ae.VaultGet(nil, "test.vault", "myservice", []byte("pass"), "")
		logger.Close()

		data, err := os.ReadFile(tmpLog)
		if err != nil {
			t.Fatalf("failed to read log: %v", err)
		}

		if !bytes.Contains(data, []byte("\"action\":\"vault_get\"")) {
			t.Errorf("log doesn't contain vault_get action")
		}
	})
}
