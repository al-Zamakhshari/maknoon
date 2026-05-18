package crypto

import (
	"context"
	"sync"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
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
	activeTunnel  *tunnel.TunnelStatus
	gateway       *tunnel.TunnelGateway
	gatewayServer *tunnel.TunnelServer
	tunnelMu      sync.RWMutex
}

// Shutdown gracefully stops all network resources held by NetworkService.
func (s *NetworkService) Shutdown(ctx context.Context) error {
	s.tunnelMu.Lock()
	defer s.tunnelMu.Unlock()

	if s.activeTunnel != nil {
		s.activeTunnel = nil
	}
	if s.gateway != nil {
		s.gateway.Stop()
		s.gateway = nil
	}
	if s.gatewayServer != nil {
		s.gatewayServer.Stop()
		s.gatewayServer = nil
	}
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
