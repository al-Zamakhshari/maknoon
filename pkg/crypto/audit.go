package crypto

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
)

// AuditLogger defines the interface for persisting engine operation logs.
type AuditLogger interface {
	Log(op string, metadata map[string]any) error
}

// NoopLogger is a strategy that discards all audit events.
type NoopLogger struct{}
func (l *NoopLogger) Log(_ string, _ map[string]any) error { return nil }

// JSONFileLogger persists audit logs to a file in JSON format.
type JSONFileLogger struct {
	Path string
}

func NewJSONFileLogger(path string) *JSONFileLogger {
	return &JSONFileLogger{Path: path}
}

func (l *JSONFileLogger) Log(op string, metadata map[string]any) error {
	f, err := os.OpenFile(l.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil { return err }
	defer f.Close()

	entry := map[string]any{
		"timestamp": time.Now().Format(time.RFC3339),
		"operation": op,
		"metadata":  metadata,
	}
	return json.NewEncoder(f).Encode(entry)
}

// AuditEngine is a decorator that adds logging to engine operations.
type AuditEngine struct {
	Engine MaknoonEngine
	Logger *slog.Logger
	Audit  AuditLogger
}

func (e *AuditEngine) log(op string, metadata map[string]any) {
	if e.Audit != nil { _ = e.Audit.Log(op, metadata) }
}

func (e *AuditEngine) Protect(ectx *EngineContext, inputName string, r io.Reader, w io.Writer, opts Options) (byte, error) {
	e.Logger.Info("engine: protect started", "input", inputName)
	e.log("protect", map[string]any{"input": inputName})
	return e.Engine.Protect(ectx, inputName, r, w, opts)
}

func (e *AuditEngine) Unprotect(ectx *EngineContext, r io.Reader, w io.Writer, outPath string, opts Options) (byte, error) {
	e.Logger.Info("engine: unprotect started", "output", outPath)
	e.log("unprotect", map[string]any{"output": outPath})
	return e.Engine.Unprotect(ectx, r, w, outPath, opts)
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

func (e *AuditEngine) IdentityRename(ectx *EngineContext, old, new string) error {
	e.Logger.Info("engine: identity rename", "from", old, "to", new)
	return e.Engine.IdentityRename(ectx, old, new)
}

func (e *AuditEngine) IdentitySplit(ectx *EngineContext, name string, t, s int, pass string) ([]string, error) {
	e.Logger.Info("engine: identity split", "name", name, "shares", s)
	return e.Engine.IdentitySplit(ectx, name, t, s, pass)
}

func (e *AuditEngine) IdentityCombine(ectx *EngineContext, m []string, out, pass string, nopass bool) (string, error) {
	e.Logger.Info("engine: identity combine", "output", out)
	return e.Engine.IdentityCombine(ectx, m, out, pass, nopass)
}

func (e *AuditEngine) IdentityPublish(ectx *EngineContext, h string, opts IdentityPublishOptions) error {
	e.Logger.Info("engine: identity publish", "handle", h)
	return e.Engine.IdentityPublish(ectx, h, opts)
}

func (e *AuditEngine) ContactAdd(ectx *EngineContext, petname, kem, sig, note string) error {
	e.Logger.Info("engine: contact add", "petname", petname)
	return e.Engine.ContactAdd(ectx, petname, kem, sig, note)
}

func (e *AuditEngine) ContactList(ectx *EngineContext) ([]*Contact, error) {
	return e.Engine.ContactList(ectx)
}

func (e *AuditEngine) VaultGet(ectx *EngineContext, path, service string, pass []byte, pin string) (*VaultEntry, error) {
	e.Logger.Info("engine: vault get", "service", service)
	return e.Engine.VaultGet(ectx, path, service, pass, pin)
}

func (e *AuditEngine) VaultSet(ectx *EngineContext, path string, entry *VaultEntry, pass []byte, pin string) error {
	e.Logger.Info("engine: vault set", "service", entry.Service)
	return e.Engine.VaultSet(ectx, path, entry, pass, pin)
}

func (e *AuditEngine) VaultRename(ectx *EngineContext, old, new string) error {
	return e.Engine.VaultRename(ectx, old, new)
}

func (e *AuditEngine) VaultDelete(ectx *EngineContext, name string) error {
	return e.Engine.VaultDelete(ectx, name)
}

func (e *AuditEngine) VaultList(ectx *EngineContext, path string) ([]string, error) {
	return e.Engine.VaultList(ectx, path)
}

func (e *AuditEngine) VaultSplit(ectx *EngineContext, path string, t, s int, pass string) ([]string, error) {
	return e.Engine.VaultSplit(ectx, path, t, s, pass)
}

func (e *AuditEngine) VaultRecover(ectx *EngineContext, m []string, path, out, pass string) (string, error) {
	return e.Engine.VaultRecover(ectx, m, path, out, pass)
}

func (e *AuditEngine) P2PSend(ectx *EngineContext, name string, r io.Reader, opts P2PSendOptions) (string, <-chan P2PStatus, error) {
	e.Logger.Info("engine: p2p send", "input", name)
	return e.Engine.P2PSend(ectx, name, r, opts)
}

func (e *AuditEngine) P2PReceive(ectx *EngineContext, code string, opts P2PReceiveOptions) (<-chan P2PStatus, error) {
	e.Logger.Info("engine: p2p receive", "code", code)
	return e.Engine.P2PReceive(ectx, code, opts)
}

func (e *AuditEngine) ValidateWormholeURL(ectx *EngineContext, u string) error {
	return e.Engine.ValidateWormholeURL(ectx, u)
}

func (e *AuditEngine) GeneratePassword(ectx *EngineContext, l int, sym bool) (string, error) {
	return e.Engine.GeneratePassword(ectx, l, sym)
}

func (e *AuditEngine) GeneratePassphrase(ectx *EngineContext, w int, sep string) (string, error) {
	return e.Engine.GeneratePassphrase(ectx, w, sep)
}

func (e *AuditEngine) GetPolicy() SecurityPolicy { return e.Engine.GetPolicy() }
func (e *AuditEngine) GetConfig() *Config        { return e.Engine.GetConfig() }

func (e *AuditEngine) UpdateConfig(ectx *EngineContext, nc *Config) error {
	e.Logger.Info("engine: config update")
	return e.Engine.UpdateConfig(ectx, nc)
}

func (e *AuditEngine) RegisterProfile(ectx *EngineContext, n string, dp *DynamicProfile) error {
	return e.Engine.RegisterProfile(ectx, n, dp)
}

func (e *AuditEngine) RemoveProfile(ectx *EngineContext, n string) error {
	return e.Engine.RemoveProfile(ectx, n)
}

func (e *AuditEngine) Inspect(ectx *EngineContext, in io.Reader) (*HeaderInfo, error) {
	return e.Engine.Inspect(ectx, in)
}

func (e *AuditEngine) TunnelStart(ectx *EngineContext, opts tunnel.TunnelOptions) (tunnel.TunnelStatus, error) {
	e.Logger.Info("engine: tunnel start", "remote", opts.RemoteEndpoint)
	return e.Engine.TunnelStart(ectx, opts)
}

func (e *AuditEngine) TunnelListen(ectx *EngineContext, addr string, w bool) (string, <-chan tunnel.TunnelStatus, error) {
	e.Logger.Info("engine: tunnel listen", "addr", addr, "wormhole", w)
	return e.Engine.TunnelListen(ectx, addr, w)
}

func (e *AuditEngine) TunnelStop(ectx *EngineContext) error {
	e.Logger.Info("engine: tunnel stop")
	return e.Engine.TunnelStop(ectx)
}

func (e *AuditEngine) TunnelStatus(ectx *EngineContext) (tunnel.TunnelStatus, error) {
	return e.Engine.TunnelStatus(ectx)
}
