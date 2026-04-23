package crypto

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// AuditLogger defines the interface for recording engine operations.
type AuditLogger interface {
	LogEvent(action string, metadata map[string]any, err error)
	Close() error
}

// NoopLogger is the default logger that does nothing (Stealth Mode).
type NoopLogger struct{}

func (l *NoopLogger) LogEvent(action string, metadata map[string]any, err error) {}
func (l *NoopLogger) Close() error                                               { return nil }

// JSONFileLogger appends structured audit logs to a file.
type JSONFileLogger struct {
	file *os.File
	mu   sync.Mutex
}

// NewJSONFileLogger creates a thread-safe JSON line logger.
func NewJSONFileLogger(path string) (*JSONFileLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	return &JSONFileLogger{file: f}, nil
}

type auditEntry struct {
	Timestamp string         `json:"timestamp"`
	Action    string         `json:"action"`
	Metadata  map[string]any `json:"metadata"`
	Status    string         `json:"status"`
	Error     string         `json:"error,omitempty"`
}

func (l *JSONFileLogger) LogEvent(action string, metadata map[string]any, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	status := "success"
	errMsg := ""
	if err != nil {
		status = "failure"
		errMsg = err.Error()
	}

	entry := auditEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Action:    action,
		Metadata:  metadata,
		Status:    status,
		Error:     errMsg,
	}

	raw, _ := json.Marshal(entry)
	fmt.Fprintln(l.file, string(raw))
}

func (l *JSONFileLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// AuditEngine wraps the core Engine to provide transparent auditing.
type AuditEngine struct {
	Engine *Engine
	Logger AuditLogger
}

func (e *AuditEngine) Protect(inputName string, r io.Reader, w io.Writer, opts Options) (byte, error) {
	start := time.Now()
	flags, err := e.Engine.Protect(inputName, r, w, opts)
	duration := time.Since(start)

	e.Logger.LogEvent("protect", map[string]any{
		"input":       inputName,
		"profile_id":  opts.ProfileID,
		"concurrency": opts.Concurrency,
		"duration_ms": duration.Milliseconds(),
		"flags":       flags,
	}, err)

	return flags, err
}

func (e *AuditEngine) Unprotect(r io.Reader, w io.Writer, outPath string, opts Options) (byte, error) {
	start := time.Now()
	flags, err := e.Engine.Unprotect(r, w, outPath, opts)
	duration := time.Since(start)

	e.Logger.LogEvent("unprotect", map[string]any{
		"output":      outPath,
		"duration_ms": duration.Milliseconds(),
		"flags":       flags,
	}, err)

	return flags, err
}

// Delegate other Engine methods to the core
func (e *AuditEngine) LoadCustomProfile(path string) (*DynamicProfile, error) {
	return e.Engine.LoadCustomProfile(path)
}

func (e *AuditEngine) GenerateRandomProfile(id byte) *DynamicProfile {
	return e.Engine.GenerateRandomProfile(id)
}

func (e *AuditEngine) ValidateProfile(p *DynamicProfile) error {
	return e.Engine.ValidateProfile(p)
}

func (e *AuditEngine) ValidateWormholeURL(u string) error {
	return e.Engine.ValidateWormholeURL(u)
}

func (e *AuditEngine) VaultGet(vaultPath string, service string, passphrase []byte, pin string) (*VaultEntry, error) {
	start := time.Now()
	entry, err := e.Engine.VaultGet(vaultPath, service, passphrase, pin)
	duration := time.Since(start)

	e.Logger.LogEvent("vault_get", map[string]any{
		"vault":       vaultPath,
		"service":     service,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return entry, err
}

func (e *AuditEngine) VaultSet(vaultPath string, entry *VaultEntry, passphrase []byte, pin string) error {
	start := time.Now()
	err := e.Engine.VaultSet(vaultPath, entry, passphrase, pin)
	duration := time.Since(start)

	var service string
	if entry != nil {
		service = entry.Service
	}

	e.Logger.LogEvent("vault_set", map[string]any{
		"vault":       vaultPath,
		"service":     service,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return err
}

func (e *AuditEngine) VaultRename(oldName, newName string) error {
	start := time.Now()
	err := e.Engine.VaultRename(oldName, newName)
	duration := time.Since(start)

	e.Logger.LogEvent("vault_rename", map[string]any{
		"old":         oldName,
		"new":         newName,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return err
}

func (e *AuditEngine) VaultDelete(name string) error {
	start := time.Now()
	err := e.Engine.VaultDelete(name)
	duration := time.Since(start)

	e.Logger.LogEvent("vault_delete", map[string]any{
		"name":        name,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return err
}

func (e *AuditEngine) GetPolicy() SecurityPolicy {
	return e.Engine.Policy
}

func (e *AuditEngine) GetConfig() *Config {
	return e.Engine.Config
}
