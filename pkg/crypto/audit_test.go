package crypto

import (
	"bytes"
	"log/slog"
	"os"
	"testing"
)

func TestAuditEngineDecorator(t *testing.T) {
	base, _ := NewEngine(&HumanPolicy{})
	mockAudit := &MockAuditLogger{Entries: make(map[string]any)}
	
	engine := &AuditEngine{
		Engine: base,
		Logger: slog.Default(),
		Audit:  mockAudit,
	}

	t.Run("ProtectLogging", func(t *testing.T) {
		ectx := NewEngineContext(nil, nil, nil)
		r := bytes.NewReader([]byte("secret"))
		w := new(bytes.Buffer)
		_, _ = engine.Protect(ectx, "test.txt", r, w, Options{})
		
		if !mockAudit.Has("protect") {
			t.Error("audit log missing protect entry")
		}
	})
}

type MockAuditLogger struct {
	Entries map[string]any
}

func (m *MockAuditLogger) Log(op string, meta map[string]any) error {
	m.Entries[op] = meta
	return nil
}

func (m *MockAuditLogger) Has(op string) bool {
	_, ok := m.Entries[op]
	return ok
}

func TestJSONFileLogger(t *testing.T) {
	path := "audit_test.json"
	defer os.Remove(path)

	logger := NewJSONFileLogger(path)
	_ = logger.Log("test_op", map[string]any{"key": "value"})

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("audit file not created")
	}
}
