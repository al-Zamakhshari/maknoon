package crypto

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
)

// AuditLogger defines the interface for recording engine operations.
type AuditLogger interface {
	LogEvent(action string, metadata map[string]any, err error)
}

// JSONFileLogger implements AuditLogger by writing to a local file.
type JSONFileLogger struct {
	Path string
	mu   sync.Mutex
}

func (l *JSONFileLogger) Close() error {
	return nil
}

// NewJSONFileLogger creates a new audit logger that writes to a file.
func NewJSONFileLogger(path string) (*JSONFileLogger, error) {
	return &JSONFileLogger{Path: path}, nil
}

func (l *JSONFileLogger) LogEvent(action string, metadata map[string]any, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := map[string]any{
		"timestamp": time.Now().Format(time.RFC3339),
		"action":    action,
		"metadata":  metadata,
	}
	if err != nil {
		entry["error"] = err.Error()
	}

	f, _ := os.OpenFile(l.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		defer f.Close()
		_ = json.NewEncoder(f).Encode(entry)
	}
}

// NoopLogger discards all audit events.
type NoopLogger struct{}
func (l *NoopLogger) LogEvent(string, map[string]any, error) {}

// AuditEngine is a decorator that records operations to an AuditLogger.
type AuditEngine struct {
	Engine *Engine
	Logger AuditLogger
}

func (e *AuditEngine) Protect(ectx *EngineContext, inputName string, r io.Reader, w io.Writer, opts Options) (byte, error) {
	start := time.Now()
	res, err := e.Engine.Protect(ectx, inputName, r, w, opts)
	duration := time.Since(start)

	e.Logger.LogEvent("protect", map[string]any{
		"input":       inputName,
		"stealth":     opts.Stealth,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return res, err
}

func (e *AuditEngine) Unprotect(ectx *EngineContext, r io.Reader, w io.Writer, outPath string, opts Options) (byte, error) {
	start := time.Now()
	res, err := e.Engine.Unprotect(ectx, r, w, outPath, opts)
	duration := time.Since(start)

	e.Logger.LogEvent("unprotect", map[string]any{
		"output_dir":  outPath,
		"duration_ms": duration.Milliseconds(),
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

func (e *AuditEngine) IdentityActive(ectx *EngineContext) ([]string, error) {
	return e.Engine.IdentityActive(ectx)
}

func (e *AuditEngine) IdentityInfo(ectx *EngineContext, name string) (string, error) {
	return e.Engine.IdentityInfo(ectx, name)
}

func (e *AuditEngine) IdentityRename(ectx *EngineContext, oldName, newName string) error {
	return e.Engine.IdentityRename(ectx, oldName, newName)
}

func (e *AuditEngine) IdentitySplit(ectx *EngineContext, name string, threshold, shares int, passphrase string) ([]string, error) {
	return e.Engine.IdentitySplit(ectx, name, threshold, shares, passphrase)
}

func (e *AuditEngine) IdentityCombine(ectx *EngineContext, mnemonics []string, output string, passphrase string, noPassword bool) (string, error) {
	return e.Engine.IdentityCombine(ectx, mnemonics, output, passphrase, noPassword)
}

func (e *AuditEngine) IdentityPublish(ectx *EngineContext, handle string, opts IdentityPublishOptions) error {
	return e.Engine.IdentityPublish(ectx, handle, opts)
}

func (e *AuditEngine) VaultGet(ectx *EngineContext, vaultPath string, service string, passphrase []byte, pin string) (*VaultEntry, error) {
	start := time.Now()
	res, err := e.Engine.VaultGet(ectx, vaultPath, service, passphrase, pin)
	duration := time.Since(start)

	e.Logger.LogEvent("vault_get", map[string]any{
		"vault":       vaultPath,
		"service":     service,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return res, err
}

func (e *AuditEngine) VaultSet(ectx *EngineContext, vaultPath string, entry *VaultEntry, passphrase []byte, pin string) error {
	start := time.Now()
	err := e.Engine.VaultSet(ectx, vaultPath, entry, passphrase, pin)
	duration := time.Since(start)

	e.Logger.LogEvent("vault_set", map[string]any{
		"vault":       vaultPath,
		"service":     entry.Service,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return err
}

func (e *AuditEngine) VaultRename(ectx *EngineContext, oldName, newName string) error {
	return e.Engine.VaultRename(ectx, oldName, newName)
}

func (e *AuditEngine) VaultDelete(ectx *EngineContext, name string) error {
	return e.Engine.VaultDelete(ectx, name)
}

func (e *AuditEngine) VaultList(ectx *EngineContext, vaultPath string) ([]string, error) {
	return e.Engine.VaultList(ectx, vaultPath)
}

func (e *AuditEngine) VaultSplit(ectx *EngineContext, vaultPath string, threshold, shares int, passphrase string) ([]string, error) {
	return e.Engine.VaultSplit(ectx, vaultPath, threshold, shares, passphrase)
}

func (e *AuditEngine) VaultRecover(ectx *EngineContext, mnemonics []string, vaultPath string, output string, passphrase string) (string, error) {
	return e.Engine.VaultRecover(ectx, mnemonics, vaultPath, output, passphrase)
}

func (e *AuditEngine) P2PSend(ectx *EngineContext, inputName string, r io.Reader, opts P2PSendOptions) (string, <-chan P2PStatus, error) {
	start := time.Now()
	code, status, err := e.Engine.P2PSend(ectx, inputName, r, opts)
	duration := time.Since(start)

	e.Logger.LogEvent("p2p_send", map[string]any{
		"input":       inputName,
		"duration_ms": duration.Milliseconds(),
	}, err)

	return code, status, err
}

func (e *AuditEngine) P2PReceive(ectx *EngineContext, code string, opts P2PReceiveOptions) (<-chan P2PStatus, error) {
	start := time.Now()
	status, err := e.Engine.P2PReceive(ectx, code, opts)
	duration := time.Since(start)

	e.Logger.LogEvent("p2p_receive", map[string]any{
		"duration_ms": duration.Milliseconds(),
	}, err)

	return status, err
}

func (e *AuditEngine) ValidateWormholeURL(ectx *EngineContext, u string) error {
	return e.Engine.ValidateWormholeURL(ectx, u)
}

func (e *AuditEngine) ContactAdd(ectx *EngineContext, petname, kemPub, sigPub, note string) error {
	return e.Engine.ContactAdd(ectx, petname, kemPub, sigPub, note)
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


func (e *AuditEngine) GetPolicy() SecurityPolicy { return e.Engine.Policy }
func (e *AuditEngine) GetConfig() *Config        { return e.Engine.Config }

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
	return e.Engine.RegisterProfile(ectx, name, dp)
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

func (e *AuditEngine) TunnelListen(ectx *EngineContext, addr string, useWormhole bool) (string, <-chan tunnel.TunnelStatus, error) {
	start := time.Now()
	code, statusCh, err := e.Engine.TunnelListen(ectx, addr, useWormhole)
	duration := time.Since(start)

	e.Logger.LogEvent("tunnel_listen", map[string]any{
		"address":      addr,
		"use_wormhole": useWormhole,
		"duration_ms":  duration.Milliseconds(),
	}, err)

	return code, statusCh, err
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
