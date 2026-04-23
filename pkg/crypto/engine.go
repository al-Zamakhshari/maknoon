package crypto

import (
	"fmt"
)

// EngineEvent is the base interface for all telemetry emitted by the Engine.
type EngineEvent interface {
	String() string
}

// EventEncryptionStarted is emitted when the protection pipeline begins.
type EventEncryptionStarted struct {
	TotalBytes int64
}

func (e EventEncryptionStarted) String() string { return "encryption started" }

// EventDecryptionStarted is emitted when the unprotection pipeline begins.
type EventDecryptionStarted struct {
	TotalBytes int64
}

func (e EventDecryptionStarted) String() string { return "decryption started" }

// EventChunkProcessed is emitted when a data chunk has been successfully processed.
type EventChunkProcessed struct {
	BytesProcessed int64
	TotalProcessed int64
}

func (e EventChunkProcessed) String() string { return "chunk processed" }

// EventHandshakeComplete is emitted when the cryptographic handshake (KEM) finishes.
type EventHandshakeComplete struct{}

func (e EventHandshakeComplete) String() string { return "handshake complete" }

// Engine is the central stateful service for Maknoon operations.
type Engine struct {
	Policy     SecurityPolicy
	Config     *Config
	Identities *IdentityManager
}

// NewEngine creates a new Engine with the specified policy and loaded config.
func NewEngine(policy SecurityPolicy) (*Engine, error) {
	conf, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize engine config: %w", err)
	}

	return &Engine{
		Policy:     policy,
		Config:     conf,
		Identities: NewIdentityManager(),
	}, nil
}

// ValidateWormholeURL enforces network boundaries.
func (e *Engine) ValidateWormholeURL(u string) error {
	return e.Policy.ValidateWormholeURL(u, e.Config.AgentLimits.AllowedURLs)
}

// ValidateProfile performs both technical sanity and policy-driven validation.
func (e *Engine) ValidateProfile(p *DynamicProfile) error {
	// 1. Technical Sanity
	if err := p.Validate(); err != nil {
		return err
	}

	// 2. Policy Enforcement
	return e.Policy.ValidateProfileResource(p.ArgonMem, p.ArgonTime, p.ArgonThrd, e.Config.AgentLimits)
}

// LoadCustomProfile reads, validates, and registers a profile under the active policy.
func (e *Engine) LoadCustomProfile(path string) (*DynamicProfile, error) {
	dp, err := LoadCustomProfile(path)
	if err != nil {
		return nil, err
	}

	if err := e.ValidateProfile(dp); err != nil {
		return nil, err
	}

	return dp, nil
}
