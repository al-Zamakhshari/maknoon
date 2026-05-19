package crypto

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
)

var _ MaknoonEngine = (*Engine)(nil)

// Engine is the central stateful service for Maknoon operations.
type Engine struct {
	Policy SecurityPolicy
	Config *Config
	Logger *slog.Logger

	// Component Services
	Vault     *VaultService
	Identity  *IdentityService
	Network   *NetworkService
	Crypto    *CryptoService
	Workspace *WorkspaceService

	// Contacts State
	Contacts     *ContactManager
	contactsMu   sync.Mutex
	contactsPath string

	// Config change listeners — fired after UpdateConfig replaces the singleton.
	configChangeMu      sync.RWMutex
	onConfigChangeHooks []func(*Config)
}

func (e *Engine) GetPolicy() SecurityPolicy { return e.Policy }
func (e *Engine) GetConfig() *Config        { return e.Config }

// OnConfigChange registers fn to be called (with a snapshot of the new Config)
// every time UpdateConfig successfully replaces the engine's configuration.
// Listeners are called synchronously after the singleton is replaced; they must
// not call UpdateConfig themselves to avoid a deadlock.
func (e *Engine) OnConfigChange(fn func(*Config)) {
	e.configChangeMu.Lock()
	defer e.configChangeMu.Unlock()
	e.onConfigChangeHooks = append(e.onConfigChangeHooks, fn)
}

func (e *Engine) UpdateConfig(ectx *EngineContext, newConf *Config) error {
	ectx = e.context(ectx)
	if !ectx.Policy.AllowConfigModification() {
		return &ErrPolicyViolation{
			Reason:     "configuration modification is prohibited under the active policy",
			PolicyName: ectx.Policy.Name(),
		}
	}

	// Phase 6.3: Threshold-bound Policy Enforcement
	threshold, peers := ectx.Policy.QuorumRequirement(string(ActionConfigAdmin))
	if threshold > 0 {
		if len(peers) == 0 {
			peers = e.Config.Governance.AdminPeers
		}
		if len(peers) == 0 {
			return &ErrPolicyViolation{
				Reason:     "administrative quorum required but no authorized peers configured",
				PolicyName: ectx.Policy.Name(),
			}
		}

		e.Logger.Info("Administrative quorum required for config update", "threshold", threshold, "peers", len(peers))

		// In a real CLI/API flow, this would be an asynchronous or multi-step process.
		// For the DI-driven engine, we attempt to gather consensus if targets are available.
		resps, err := e.QuorumRequest(ectx, e.Config.DefaultIdentity, peers, ActionConfigAdmin, "global_config", "Update system configuration")
		if err != nil {
			return fmt.Errorf("administrative quorum request failed: %w", err)
		}

		approvals := 0
		for _, r := range resps {
			if r.Approved {
				approvals++
			}
		}

		if approvals < threshold {
			return &ErrPolicyViolation{
				Reason:     fmt.Sprintf("administrative quorum failed: received %d approvals, required %d", approvals, threshold),
				PolicyName: ectx.Policy.Name(),
			}
		}
		e.Logger.Info("Administrative quorum achieved", "approvals", approvals)
	}

	if err := newConf.Validate(); err != nil {
		return err
	}
	if err := newConf.Save(); err != nil {
		return err
	}
	e.Config = newConf
	e.Identity.Mgr.Config = newConf

	// Notify registered listeners with a snapshot of the new config.
	e.configChangeMu.RLock()
	hooks := make([]func(*Config), len(e.onConfigChangeHooks))
	copy(hooks, e.onConfigChangeHooks)
	e.configChangeMu.RUnlock()
	snap := newConf.Clone()
	for _, fn := range hooks {
		fn(snap)
	}
	return nil
}

func NewEngine(policy SecurityPolicy, idMgr *IdentityManager, conf *Config, vaultStore VaultStore, logger *slog.Logger) (*Engine, error) {
	if conf == nil {
		var err error
		conf, err = LoadConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize engine config: %w", err)
		}
	}

	if err := conf.Validate(); err != nil {
		return nil, fmt.Errorf("invalid engine config: %w", err)
	}

	if idMgr == nil {
		idMgr = NewIdentityManager()
	}
	idMgr.Config = conf

	if vaultStore == nil {
		vaultStore = &FileSystemVaultStore{
			BaseDir: conf.Paths.VaultsDir,
			Backend: conf.VaultBackend,
		}
	}

	if logger == nil {
		logger = slog.Default()
	}

	e := &Engine{
		Policy:       policy,
		Config:       conf,
		Logger:       logger,
		contactsPath: filepath.Join(conf.Paths.VaultsDir, "..", "contacts.db"),
	}

	// Initialize Services
	e.Vault = &VaultService{engine: e, Store: vaultStore}
	e.Identity = &IdentityService{engine: e, Mgr: idMgr}
	e.Network = &NetworkService{engine: e}
	e.Crypto = &CryptoService{engine: e}
	e.Workspace = &WorkspaceService{engine: e}

	// P2P transport removed — IdentityPublish will use static Multiaddrs from opts only.
	e.Identity.Mgr.P2P = nil
	return e, nil
}

func (e *Engine) context(ectx *EngineContext) *EngineContext {
	if ectx == nil {
		return &EngineContext{
			Context: context.Background(),
			Policy:  e.Policy,
		}
	}
	if ectx.Policy == nil {
		ectx.Policy = e.Policy
	}
	if ectx.Context == nil {
		ectx.Context = context.Background()
	}
	return ectx
}

func (e *Engine) enforce(ectx *EngineContext, cap Capability) error {
	if !ectx.Policy.HasCapability(cap) {
		return &ErrPolicyViolation{
			Capability: string(cap),
			PolicyName: ectx.Policy.Name(),
		}
	}
	return nil
}

// newShimEngine returns a minimal engine for legacy package-level Protect/Unprotect shims
// (used by pipeline.go). Only Crypto and Workspace services are initialized.
// Vault, Identity, Network, and Contacts are nil — do not call methods that require them.
// This exists solely so that the pipeline package-level helpers can share policy/config
// without a full engine initialization.
//
// Deprecated: use NewStreamEngine instead.
func newShimEngine(conf *Config) *Engine {
	if conf == nil {
		conf = GetGlobalConfig()
	}
	e := &Engine{
		Policy: &HumanPolicy{},
		Config: conf,
		Logger: slog.Default(),
	}
	e.Crypto = &CryptoService{engine: e}
	e.Workspace = &WorkspaceService{engine: e}
	return e
}

// NewStreamEngine creates a crypto-only engine suitable for stream encrypt/decrypt
// operations that don't require vault, identity, network, or contact services.
// If conf is nil, the global config is used.
//
// Note: Vault, Identity, Network, and Contacts are nil on the returned engine.
// Panics or errors will occur if methods that require those services are called.
func NewStreamEngine(conf *Config) *Engine {
	return newShimEngine(conf)
}

func (e *Engine) Close() error {
	if e.Contacts != nil {
		return e.Contacts.Close()
	}
	return nil
}

// Shutdown performs a graceful shutdown of all engine subsystems:
// network (tunnel + gateway), audit log flush, and contacts DB.
func (e *Engine) Shutdown(ctx context.Context) error {
	// 1. Close network (tunnel + gateway)
	if e.Network != nil {
		if err := e.Network.Shutdown(ctx); err != nil {
			e.Logger.Warn("network shutdown error", "err", err)
		}
	}
	// 2. Flush audit log if present
	if al, ok := e.Logger.Handler().(interface{ Flush() error }); ok {
		_ = al.Flush()
	}
	// 3. Close contacts DB
	return e.Close()
}

func SafeClear(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, ChunkSize+256)
		return &b
	},
}
