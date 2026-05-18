package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// DeriveSigningKeyFromSeed generates a deterministic ML-DSA-87 private key from a 32-byte seed.
func DeriveSigningKeyFromSeed(seed []byte) ([]byte, error) {
	if len(seed) < 32 {
		return nil, fmt.Errorf("seed too short for ML-DSA (min 32 bytes)")
	}
	_, sk, err := mldsa87.GenerateKey(bytes.NewReader(seed))
	if err != nil {
		return nil, err
	}
	return sk.MarshalBinary()
}

// AuditLogger defines the interface for recording engine operations.
type AuditLogger interface {
	LogEvent(action string, metadata map[string]any, err error)
	SetSigningKey(key []byte)
	Close() error
}

// NoopLogger is the default logger that does nothing (Stealth Mode).
type NoopLogger struct{}

func (l *NoopLogger) LogEvent(action string, metadata map[string]any, err error) {}
func (l *NoopLogger) SetSigningKey(key []byte)                                   {}
func (l *NoopLogger) Close() error                                               { return nil }

// JSONFileLogger appends structured, hash-chained audit logs to a file.
// Each entry is signed with ML-DSA-87 if a signing key is configured.
type JSONFileLogger struct {
	file       *os.File
	signingKey []byte
	lastHash   string
	mu         sync.Mutex
}

// NewJSONFileLogger creates a thread-safe JSON line logger.
func NewJSONFileLogger(path string) (*JSONFileLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	return &JSONFileLogger{file: f}, nil
}

func (l *JSONFileLogger) SetSigningKey(key []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.signingKey = key
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

	entry := AuditEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		PrevHash:  l.lastHash,
		Action:    action,
		Metadata:  metadata,
		Status:    status,
		Error:     errMsg,
	}

	// Sign the entry to prevent forensic tampering (FIPS 140-3 integrity).
	if l.signingKey != nil {
		raw, _ := json.Marshal(entry)
		sig, sigErr := SignData(raw, l.signingKey)
		if sigErr == nil {
			entry.Signature = hex.EncodeToString(sig)
		}
	}

	raw, _ := json.Marshal(entry)
	fmt.Fprintln(l.file, string(raw))

	// Update chain hash for next entry (FIPS 140-3 Forensic Chaining).
	h := sha256.Sum256(raw)
	l.lastHash = hex.EncodeToString(h[:])
}

func (l *JSONFileLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// ConsoleAuditLogger prints audit events to a writer (e.g., os.Stderr).
type ConsoleAuditLogger struct {
	Writer io.Writer
}

func (l *ConsoleAuditLogger) LogEvent(action string, metadata map[string]any, err error) {
	status := "SUCCESS"
	if err != nil {
		status = fmt.Sprintf("FAILURE (%v)", err)
	}
	fmt.Fprintf(l.Writer, "AUDIT: %s | Action: %s | Status: %s | Meta: %v\n",
		time.Now().Format("15:04:05"), action, status, metadata)
}

func (l *ConsoleAuditLogger) SetSigningKey(key []byte) {}

func (l *ConsoleAuditLogger) Close() error { return nil }
