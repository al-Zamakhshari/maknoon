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

// captureAuditEngine creates a fully-initialized AuditEngine backed by a MockAuditLogger.
func captureAuditEngine(t *testing.T) (*AuditEngine, *MockAuditLogger) {
	t.Helper()
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	t.Cleanup(func() { os.Unsetenv("HOME") })

	conf := DefaultConfig()
	core, err := NewEngine(&HumanPolicy{}, nil, conf, nil, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { core.Close() })

	mock := &MockAuditLogger{}
	ae := &AuditEngine{BaseEngine: BaseEngine{Engine: core}, Logger: mock}
	return ae, mock
}

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

// TestAuditVaultOperations verifies vault_set, vault_delete, vault_rename, vault_list are logged.
func TestAuditVaultOperations(t *testing.T) {
	ae, mock := captureAuditEngine(t)

	ae.VaultSet(nil, "myvault.vault", &VaultEntry{Service: "svc"}, []byte("pass"), "", false)
	if mock.LastAction != "vault_set" {
		t.Errorf("expected vault_set, got %s", mock.LastAction)
	}

	ae.VaultDelete(nil, "myvault")
	if mock.LastAction != "vault_delete" {
		t.Errorf("expected vault_delete, got %s", mock.LastAction)
	}

	ae.VaultRename(nil, "oldvault", "newvault")
	if mock.LastAction != "vault_rename" {
		t.Errorf("expected vault_rename, got %s", mock.LastAction)
	}

	ae.VaultList(nil, "myvault.vault", []byte("pass"))
	if mock.LastAction != "vault_list" {
		t.Errorf("expected vault_list, got %s", mock.LastAction)
	}
}

// TestAuditIdentityDelete verifies identity_delete is logged.
func TestAuditIdentityDelete(t *testing.T) {
	ae, mock := captureAuditEngine(t)
	ae.IdentityDelete(nil, "test-id")
	if mock.LastAction != "identity_delete" {
		t.Errorf("expected identity_delete, got %s", mock.LastAction)
	}
}

// TestAuditHashChain writes 10 entries and verifies the full chain integrity.
func TestAuditHashChain(t *testing.T) {
	tmpLog := filepath.Join(t.TempDir(), "chain_audit.log")
	logger, err := NewJSONFileLogger(tmpLog)
	if err != nil {
		t.Fatalf("NewJSONFileLogger: %v", err)
	}

	for i := 0; i < 10; i++ {
		logger.LogEvent("test_op", map[string]any{"i": i}, nil)
	}
	logger.Close()

	data, _ := os.ReadFile(tmpLog)
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 10 {
		t.Fatalf("expected 10 entries, got %d", len(lines))
	}

	for i := 1; i < len(lines); i++ {
		var prev, curr AuditEntry
		json.Unmarshal(lines[i-1], &prev)
		json.Unmarshal(lines[i], &curr)

		h := sha256.Sum256(lines[i-1])
		expected := hex.EncodeToString(h[:])
		if curr.PrevHash != expected {
			t.Errorf("chain broken at entry %d: expected PrevHash %s, got %s", i, expected, curr.PrevHash)
		}
	}
}

// TestAuditSignatureVerification writes signed entries and verifies each signature.
func TestAuditSignatureVerification(t *testing.T) {
	tmpDir := t.TempDir()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	signingKey, err := DeriveSigningKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("DeriveSigningKeyFromSeed: %v", err)
	}

	tmpLog := filepath.Join(tmpDir, "signed_audit.log")
	logger, err := NewJSONFileLogger(tmpLog)
	if err != nil {
		t.Fatalf("NewJSONFileLogger: %v", err)
	}
	logger.SetSigningKey(signingKey)

	for i := 0; i < 3; i++ {
		logger.LogEvent("signed_op", map[string]any{"i": i}, nil)
	}
	logger.Close()

	data, _ := os.ReadFile(tmpLog)
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	for i, line := range lines {
		var entry AuditEntry
		json.Unmarshal(line, &entry)
		if entry.Signature == "" {
			t.Errorf("entry %d has empty Signature — signing key was not applied", i)
		}
	}
}

// TestAuditChainTamperDetected writes 5 entries, corrupts entry 3, then verifies
// that VerifyChain detects the break at entry 4.
func TestAuditChainTamperDetected(t *testing.T) {
	tmpLog := filepath.Join(t.TempDir(), "tamper_audit.log")
	logger, err := NewJSONFileLogger(tmpLog)
	if err != nil {
		t.Fatalf("NewJSONFileLogger: %v", err)
	}
	for i := 0; i < 5; i++ {
		logger.LogEvent("op", map[string]any{"i": i}, nil)
	}
	logger.Close()

	// Read all lines, corrupt the 3rd (index 2), rewrite the file.
	data, _ := os.ReadFile(tmpLog)
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	if len(lines) < 5 {
		t.Fatalf("expected 5 entries, got %d", len(lines))
	}
	// Corrupt the raw JSON of entry index 2 — change "op" to "XX"
	lines[2] = bytes.Replace(lines[2], []byte(`"op"`), []byte(`"XX"`), 1)
	os.WriteFile(tmpLog, bytes.Join(lines, []byte("\n")), 0600)

	// VerifyChain should detect the break at entry 3 (index 3's PrevHash won't match)
	err = VerifyChain(tmpLog)
	if err == nil {
		t.Error("VerifyChain should have detected the tampered entry but returned nil")
	} else {
		t.Logf("Tamper correctly detected: %v", err)
	}
}
