package crypto

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
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

// ConsoleAuditLogger prints audit events to a writer (e.g., Stderr).
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

func (l *ConsoleAuditLogger) Close() error { return nil }

// AuditEngine wraps the core Engine to provide transparent auditing.
type AuditEngine struct {
	Engine *Engine
	Logger AuditLogger
}

func (e *AuditEngine) sanitizePath(path string) string {
	if path == "-" || path == "" {
		return path
	}
	home := GetUserHomeDir()
	if strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return filepath.Base(path)
}

func (e *AuditEngine) Protect(ectx *EngineContext, inputName string, r io.Reader, w io.Writer, opts Options) (EncryptResult, error) {
	start := time.Now()
	res, err := e.Engine.Protect(ectx, inputName, r, w, opts)
	duration := time.Since(start)

	metadata := map[string]any{
		"input":       e.sanitizePath(inputName),
		"duration_ms": duration.Milliseconds(),
		"flags":       res.Flags,
	}

	if opts.ProfileID != nil {
		metadata["profile_id"] = *opts.ProfileID
	}
	if opts.Concurrency != nil {
		metadata["concurrency"] = *opts.Concurrency
	}

	e.Logger.LogEvent("protect", metadata, err)

	return res, err
}

func (e *AuditEngine) Unprotect(ectx *EngineContext, r io.Reader, w io.Writer, outPath string, opts Options) (DecryptResult, error) {
	start := time.Now()
	res, err := e.Engine.Unprotect(ectx, r, w, outPath, opts)
	duration := time.Since(start)

	e.Logger.LogEvent("unprotect", map[string]any{
		"output":      e.sanitizePath(outPath),
		"duration_ms": duration.Milliseconds(),
		"flags":       res.Flags,
	}, err)

	return res, err
}

func (e *AuditEngine) FinalizeRestoration(ectx *EngineContext, pr io.Reader, w io.Writer, flags byte, outPath string, logger *slog.Logger) error {
	return e.Engine.FinalizeRestoration(ectx, pr, w, flags, outPath, logger)
}

func (e *AuditEngine) LoadCustomProfile(ectx *EngineContext, path string) (*DynamicProfile, error) {
	return e.Engine.LoadCustomProfile(ectx, path)
}

func (e *AuditEngine) GenerateRandomProfile(ectx *EngineContext, id byte) *DynamicProfile {
	return e.Engine.GenerateRandomProfile(ectx, id)
}

func (e *AuditEngine) ValidateProfile(ectx *EngineContext, p *DynamicProfile) error {
	return e.Engine.ValidateProfile(ectx, p)
}

func (e *AuditEngine) ValidateWormholeURL(ectx *EngineContext, u string) error {
	return e.Engine.ValidateWormholeURL(ectx, u)
}

func (e *AuditEngine) VaultGet(ectx *EngineContext, vaultPath string, service string, passphrase []byte, pin string) (*VaultEntry, error) {
	start := time.Now()
	entry, err := e.Engine.VaultGet(ectx, vaultPath, service, passphrase, pin)
	duration := time.Since(start)

	e.Logger.LogEvent("vault_get", map[string]any{
		"vault":       e.sanitizePath(vaultPath),
		"service":     service,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return entry, err
}

func (e *AuditEngine) VaultSet(ectx *EngineContext, vaultPath string, entry *VaultEntry, passphrase []byte, pin string) error {
	start := time.Now()
	err := e.Engine.VaultSet(ectx, vaultPath, entry, passphrase, pin)
	duration := time.Since(start)

	var service string
	if entry != nil {
		service = entry.Service
	}

	e.Logger.LogEvent("vault_set", map[string]any{
		"vault":       e.sanitizePath(vaultPath),
		"service":     service,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return err
}

func (e *AuditEngine) VaultRename(ectx *EngineContext, oldName, newName string) error {
	start := time.Now()
	err := e.Engine.VaultRename(ectx, oldName, newName)
	duration := time.Since(start)

	e.Logger.LogEvent("vault_rename", map[string]any{
		"old":         e.sanitizePath(oldName),
		"new":         e.sanitizePath(newName),
		"duration_ms": duration.Milliseconds(),
	}, err)

	return err
}

func (e *AuditEngine) VaultDelete(ectx *EngineContext, name string) error {
	start := time.Now()
	err := e.Engine.VaultDelete(ectx, name)
	duration := time.Since(start)

	e.Logger.LogEvent("vault_delete", map[string]any{
		"name":        e.sanitizePath(name),
		"duration_ms": duration.Milliseconds(),
	}, err)

	return err
}

func (e *AuditEngine) VaultList(ectx *EngineContext, vaultPath string) ([]string, error) {
	return e.Engine.VaultList(ectx, vaultPath)
}

func (e *AuditEngine) VaultSplit(ectx *EngineContext, vaultPath string, threshold, shares int, passphrase string) ([]string, error) {
	start := time.Now()
	shards, err := e.Engine.VaultSplit(ectx, vaultPath, threshold, shares, passphrase)
	duration := time.Since(start)

	e.Logger.LogEvent("vault_split", map[string]any{
		"vault":       e.sanitizePath(vaultPath),
		"duration_ms": duration.Milliseconds(),
	}, err)

	return shards, err
}

func (e *AuditEngine) VaultRecover(ectx *EngineContext, mnemonics []string, vaultPath string, output string, passphrase string) (string, error) {
	start := time.Now()
	path, err := e.Engine.VaultRecover(ectx, mnemonics, vaultPath, output, passphrase)
	duration := time.Since(start)

	e.Logger.LogEvent("vault_recover", map[string]any{
		"vault":       e.sanitizePath(vaultPath),
		"duration_ms": duration.Milliseconds(),
	}, err)

	return path, err
}

func (e *AuditEngine) P2PSend(ectx *EngineContext, identityName, inputName string, r io.Reader, opts P2PSendOptions) (string, <-chan P2PStatus, error) {
	start := time.Now()
	code, status, err := e.Engine.P2PSend(ectx, identityName, inputName, r, opts)
	duration := time.Since(start)

	e.Logger.LogEvent("p2p_send", map[string]any{
		"identity":    identityName,
		"input":       inputName,
		"target":      opts.To,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return code, status, err
}

func (e *AuditEngine) P2PReceive(ectx *EngineContext, identityName, code string, opts P2PReceiveOptions) (<-chan P2PStatus, error) {
	start := time.Now()
	status, err := e.Engine.P2PReceive(ectx, identityName, code, opts)
	duration := time.Since(start)

	e.Logger.LogEvent("p2p_receive", map[string]any{
		"identity":    identityName,
		"code":        code,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return status, err
}

func (e *AuditEngine) IdentityActive(ectx *EngineContext) ([]string, error) {
	return e.Engine.IdentityActive(ectx)
}

func (e *AuditEngine) IdentityInfo(ectx *EngineContext, name string) (string, error) {
	return e.Engine.IdentityInfo(ectx, name)
}

func (e *AuditEngine) IdentityRename(ectx *EngineContext, oldName, newName string) error {
	start := time.Now()
	err := e.Engine.IdentityRename(ectx, oldName, newName)
	duration := time.Since(start)

	e.Logger.LogEvent("identity_rename", map[string]any{
		"old":         e.sanitizePath(oldName),
		"new":         e.sanitizePath(newName),
		"duration_ms": duration.Milliseconds(),
	}, err)

	return err
}

func (e *AuditEngine) IdentitySplit(ectx *EngineContext, name string, threshold, shares int, passphrase string) ([]string, error) {
	start := time.Now()
	shards, err := e.Engine.IdentitySplit(ectx, name, threshold, shares, passphrase)
	duration := time.Since(start)

	e.Logger.LogEvent("identity_split", map[string]any{
		"name":        e.sanitizePath(name),
		"threshold":   threshold,
		"shares":      shares,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return shards, err
}

func (e *AuditEngine) IdentityPublish(ectx *EngineContext, handle string, opts IdentityPublishOptions) error {
	start := time.Now()
	err := e.Engine.IdentityPublish(ectx, handle, opts)
	duration := time.Since(start)

	e.Logger.LogEvent("identity_publish", map[string]any{
		"handle":      handle,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return err
}

func (e *AuditEngine) IdentityCombine(ectx *EngineContext, mnemonics []string, output, passphrase string, noPassword bool) (string, error) {
	start := time.Now()
	path, err := e.Engine.IdentityCombine(ectx, mnemonics, output, passphrase, noPassword)
	duration := time.Since(start)

	e.Logger.LogEvent("identity_combine", map[string]any{
		"output":      e.sanitizePath(output),
		"duration_ms": duration.Milliseconds(),
	}, err)

	return path, err
}

func (e *AuditEngine) ContactAdd(ectx *EngineContext, petname, kemPub, sigPub, note string) error {
	start := time.Now()
	err := e.Engine.ContactAdd(ectx, petname, kemPub, sigPub, note)
	duration := time.Since(start)

	e.Logger.LogEvent("contact_add", map[string]any{
		"petname":     petname,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return err
}

func (e *AuditEngine) ContactList(ectx *EngineContext) ([]*Contact, error) {
	return e.Engine.ContactList(ectx)
}

func (e *AuditEngine) GeneratePassword(ectx *EngineContext, length int, noSymbols bool) (string, error) {
	return e.Engine.GeneratePassword(ectx, length, noSymbols)
}

func (e *AuditEngine) GeneratePassphrase(ectx *EngineContext, words int, separator string) (string, error) {
	return e.Engine.GeneratePassphrase(ectx, words, separator)
}

func (e *AuditEngine) SecureDelete(path string) error {
	start := time.Now()
	err := e.Engine.SecureDelete(path)
	duration := time.Since(start)

	e.Logger.LogEvent("secure_delete", map[string]any{
		"path":        e.sanitizePath(path),
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

func (e *AuditEngine) UpdateConfig(ectx *EngineContext, newConf *Config) error {
	start := time.Now()
	err := e.Engine.UpdateConfig(ectx, newConf)
	duration := time.Since(start)

	e.Logger.LogEvent("update_config", map[string]any{
		"duration_ms": duration.Milliseconds(),
	}, err)

	return err
}

func (e *AuditEngine) RegisterProfile(ectx *EngineContext, name string, dp *DynamicProfile) error {
	start := time.Now()
	err := e.Engine.RegisterProfile(ectx, name, dp)
	duration := time.Since(start)

	e.Logger.LogEvent("register_profile", map[string]any{
		"name":        name,
		"profile_id":  dp.ID(),
		"duration_ms": duration.Milliseconds(),
	}, err)

	return err
}

func (e *AuditEngine) RemoveProfile(ectx *EngineContext, name string) error {
	start := time.Now()
	err := e.Engine.RemoveProfile(ectx, name)
	duration := time.Since(start)

	e.Logger.LogEvent("remove_profile", map[string]any{
		"name":        name,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return err
}

func (e *AuditEngine) Diagnostic() DiagnosticResult {
	return e.Engine.Diagnostic()
}

func (e *AuditEngine) NetworkStatus(ectx *EngineContext) (NetStatusResult, error) {
	return e.Engine.NetworkStatus(ectx)
}

func (e *AuditEngine) AuditExport(ectx *EngineContext) ([]AuditEntry, error) {
	return e.Engine.AuditExport(ectx)
}

func (e *AuditEngine) Inspect(ectx *EngineContext, in io.Reader) (*HeaderInfo, error) {
	return e.Engine.Inspect(ectx, in)
}

func (e *AuditEngine) TunnelStart(ectx *EngineContext, opts tunnel.TunnelOptions) (tunnel.TunnelStatus, error) {
	start := time.Now()
	status, err := e.Engine.TunnelStart(ectx, opts)
	duration := time.Since(start)

	e.Logger.LogEvent("tunnel_start", map[string]any{
		"remote":      opts.RemoteEndpoint,
		"proxy_port":  opts.LocalProxyPort,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return status, err
}

func (e *AuditEngine) TunnelStop(ectx *EngineContext) error {
	start := time.Now()
	err := e.Engine.TunnelStop(ectx)
	duration := time.Since(start)

	e.Logger.LogEvent("tunnel_stop", map[string]any{
		"duration_ms": duration.Milliseconds(),
	}, err)

	return err
}

func (e *AuditEngine) TunnelStatus(ectx *EngineContext) (tunnel.TunnelStatus, error) {
	return e.Engine.TunnelStatus(ectx)
}

func (e *AuditEngine) ChatStart(ectx *EngineContext, identityName string, target string) (*P2PChatSession, error) {
	start := time.Now()
	sess, err := e.Engine.ChatStart(ectx, identityName, target)
	duration := time.Since(start)

	e.Logger.LogEvent("chat_start", map[string]any{
		"identity":    identityName,
		"target":      target,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return sess, err
}
