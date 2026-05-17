package crypto

import (
	"sync"
)

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

// NetworkService handles P2P and tunneling logic.
type NetworkService struct {
	engine *Engine

	// Tunnel State
	activeTunnel  interface{}
	gateway       interface{}
	gatewayServer interface{}
	tunnelMu      sync.RWMutex
}

// CryptoService handles low-level cryptographic orchestration.
type CryptoService struct {
	engine *Engine
}

// WorkspaceService handles ephemeral environments.
type WorkspaceService struct {
	engine *Engine
}
