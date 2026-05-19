package crypto

import "context"

// VaultService handles secure credential storage logic.
type VaultService struct {
	engine *Engine
	Store  VaultStore
}

// IdentityService handles identity lifecycle and discovery logic.
type IdentityService struct {
	engine *Engine
	Mgr    *IdentityManager
}

// NetworkService handles identity registry and observability logic.
type NetworkService struct {
	engine *Engine
}

// Shutdown gracefully stops all network resources held by NetworkService.
func (s *NetworkService) Shutdown(_ context.Context) error {
	return nil
}

// CryptoService handles low-level cryptographic orchestration.
type CryptoService struct {
	engine *Engine
}

// WorkspaceService handles ephemeral environments.
type WorkspaceService struct {
	engine *Engine
}
