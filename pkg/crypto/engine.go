package crypto

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
)

// Engine is the central stateful service for Maknoon operations.
type Engine struct {
	Policy     SecurityPolicy
	Config     *Config
	Identities *IdentityManager
	Vaults     VaultStore
	Contacts   *ContactManager
	Logger     *slog.Logger

	// Contacts State
	contactsMu   sync.Mutex
	contactsPath string

	// Tunnel State
	activeTunnel  interface{}
	gateway       interface{}
	gatewayServer interface{}
	tunnelMu      sync.RWMutex
}

func (e *Engine) GetPolicy() SecurityPolicy { return e.Policy }
func (e *Engine) GetConfig() *Config        { return e.Config }

func (e *Engine) UpdateConfig(ectx *EngineContext, newConf *Config) error {
	ectx = e.context(ectx)
	if !ectx.Policy.AllowConfigModification() {
		return &ErrPolicyViolation{Reason: "configuration modification is prohibited under the active policy"}
	}
	if err := newConf.Validate(); err != nil {
		return err
	}
	if err := newConf.Save(); err != nil {
		return err
	}
	e.Config = newConf
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
		Identities:   idMgr,
		Vaults:       vaultStore,
		Logger:       logger,
		contactsPath: filepath.Join(conf.Paths.VaultsDir, "..", "contacts.db"),
	}

	e.Identities.P2P = e
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
		return &ErrPolicyViolation{Reason: fmt.Sprintf("capability '%s' is prohibited under the active policy", cap)}
	}
	return nil
}

func (e *Engine) Close() error {
	if e.Contacts != nil {
		return e.Contacts.Close()
	}
	return nil
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
