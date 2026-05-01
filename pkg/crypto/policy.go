package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Capability defines a specific permission within the Maknoon system.
type Capability string

const (
	CapProtect     Capability = "protect"
	CapUnprotect   Capability = "unprotect"
	CapVaultRead   Capability = "vault_read"
	CapVaultWrite  Capability = "vault_write"
	CapVaultDelete Capability = "vault_delete"
	CapIdentity    Capability = "identity"
	CapConfig      Capability = "config"
	CapP2P         Capability = "p2p"
	CapCrypto      Capability = "crypto"
	CapAudit       Capability = "audit"
)

// SecurityPolicy defines the behavioral boundaries and capabilities of the engine.
// It implements the 'Policy Provider Pattern', allowing the engine core to remain
// agnostic of its execution environment (e.g., Human vs. AI Agent) while
// enforcing environment-specific security constraints.
type SecurityPolicy interface {
	// Name returns a human-readable name for the policy (e.g., "Human", "Agent").
	Name() string
	// HasCapability checks if the policy permits a specific functional action.
	HasCapability(cap Capability) bool

	// ValidatePath ensures a filesystem path is permitted under the policy.
	// This is the primary defense against path traversal and sandbox escape.
	ValidatePath(path string) error

	// ValidateWormholeURL ensures a network endpoint is permitted.
	ValidateWormholeURL(url string, allowed []string) error

	// ClampConcurrency returns the allowed number of parallel workers.
	ClampConcurrency(requested int, maxAllowed int) int

	// ClampProfileGeneration caps the KDF parameters during random generation to prevent DoS.
	ClampProfileGeneration(maxTime, maxMem uint32, maxThrd uint8) (uint32, uint32, uint8)

	// ValidateProfileResource ensures a cryptographic profile does not exceed resource ceilings.
	ValidateProfileResource(memKB, time uint32, threads uint8, limits AgentLimitsConfig) error

	// AllowConfigModification returns true if global configuration changes are permitted.
	AllowConfigModification() bool

	// IsAgent returns true if this is a restricted agent policy (used for UI-branching).
	IsAgent() bool
}

// HumanPolicy represents an unrestricted user-driven session.
type HumanPolicy struct{}

func (p *HumanPolicy) Name() string { return "human" }

func (p *HumanPolicy) HasCapability(cap Capability) bool { return true }

func (p *HumanPolicy) ValidatePath(path string) error                 { return nil }
func (p *HumanPolicy) ValidateWormholeURL(u string, a []string) error { return nil }
func (p *HumanPolicy) ClampConcurrency(req, max int) int {
	if req <= 0 {
		return 0 // Auto-detect
	}
	return req
}
func (p *HumanPolicy) ClampProfileGeneration(t, m uint32, th uint8) (uint32, uint32, uint8) {
	return t, m, th
}
func (p *HumanPolicy) ValidateProfileResource(m, t uint32, th uint8, l AgentLimitsConfig) error {
	return nil
}
func (p *HumanPolicy) AllowConfigModification() bool { return true }
func (p *HumanPolicy) IsAgent() bool                 { return false }

// AgentPolicy represents a restricted sandbox for autonomous agents.
type AgentPolicy struct{}

func (p *AgentPolicy) Name() string { return "agent" }

func (p *AgentPolicy) HasCapability(cap Capability) bool {
	switch cap {
	case CapVaultDelete:
		return false
	default:
		return true
	}
}

func (p *AgentPolicy) ValidatePath(path string) error {
	return ValidatePath(path, true)
}

func (p *AgentPolicy) ValidateWormholeURL(u string, allowed []string) error {
	if u == "" {
		return nil
	}
	for _, a := range allowed {
		if u == a {
			return nil
		}
	}
	return &ErrPolicyViolation{
		Reason: fmt.Sprintf("unauthorized network endpoint '%s' is prohibited in agent mode", u),
	}
}

func (p *AgentPolicy) ClampConcurrency(req, max int) int {
	if req <= 0 || req > max {
		return max
	}
	return req
}

func (p *AgentPolicy) ClampProfileGeneration(maxTime, maxMem uint32, maxThrd uint8) (uint32, uint32, uint8) {
	return maxTime, maxMem, maxThrd
}

func (p *AgentPolicy) ValidateProfileResource(memKB, time uint32, threads uint8, limits AgentLimitsConfig) error {
	if memKB > limits.MaxMemoryKB {
		return &ErrPolicyViolation{
			Reason: fmt.Sprintf("profile memory (%d KB) exceeds maximum allowed (%d KB)", memKB, limits.MaxMemoryKB),
		}
	}
	if time > limits.MaxTime {
		return &ErrPolicyViolation{
			Reason: fmt.Sprintf("profile time iterations (%d) exceeds maximum allowed (%d)", time, limits.MaxTime),
		}
	}
	if threads > limits.MaxThreads {
		return &ErrPolicyViolation{
			Reason: fmt.Sprintf("profile threads (%d) exceeds maximum allowed (%d)", threads, limits.MaxThreads),
		}
	}
	return nil
}

func (p *AgentPolicy) AllowConfigModification() bool { return true }
func (p *AgentPolicy) IsAgent() bool                 { return true }

// ValidatePath is the internal implementation of path restricted mode.
func ValidatePath(path string, restricted bool) error {
	if path == "-" || path == "" {
		return nil
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	evalPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		parentEval, err2 := filepath.EvalSymlinks(filepath.Dir(absPath))
		if err2 == nil {
			evalPath = filepath.Join(parentEval, filepath.Base(absPath))
		} else {
			evalPath = absPath
		}
	}

	if restricted {
		home, _ := os.UserHomeDir()
		evalHome, _ := filepath.EvalSymlinks(home)
		tmp := os.TempDir()
		evalTmp, _ := filepath.EvalSymlinks(tmp)

		if !strings.HasPrefix(evalPath, evalHome) && !strings.HasPrefix(evalPath, evalTmp) {
			// Specifically check for common temp/var paths that might not be captured by os.TempDir
			if !strings.HasPrefix(evalPath, "/tmp") &&
				!strings.HasPrefix(evalPath, "/private/tmp") &&
				!strings.HasPrefix(evalPath, "/var/folders") &&
				!strings.HasPrefix(evalPath, "/private/var/folders") {
				return &ErrPolicyViolation{
					Reason: "arbitrary file paths outside home or temp are prohibited",
					Path:   evalPath,
				}
			}
		}
	}

	return nil
}
