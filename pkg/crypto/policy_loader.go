package crypto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// FilePolicy implements SecurityPolicy using a declarative JSON schema.
type FilePolicy struct {
	PolicyName string        `json:"name"`
	Rules      []PolicyRule  `json:"rules"`
	Limits     ResourceLimit `json:"limits"`
}

type PolicyRule struct {
	Type   string   `json:"type"`             // capability, path, url
	Action string   `json:"action"`           // allow, deny
	Values []string `json:"values,omitempty"` // cap names, regex patterns
}

type ResourceLimit struct {
	MaxMemoryKB uint32 `json:"max_memory_kb"`
	MaxTime     uint32 `json:"max_time"`
	MaxThreads  uint8  `json:"max_threads"`
}

func (p *FilePolicy) Name() string { return p.PolicyName }

func (p *FilePolicy) HasCapability(cap Capability) bool {
	hasRules := false
	allowed := false
	explicitDeny := false

	for _, r := range p.Rules {
		if r.Type == "capability" {
			hasRules = true
			for _, v := range r.Values {
				if Capability(v) == cap {
					if r.Action == "deny" {
						explicitDeny = true
					}
					if r.Action == "allow" {
						allowed = true
					}
				}
			}
		}
	}

	if explicitDeny {
		return false
	}
	if !hasRules {
		return true // Allow by default if no capability rules defined
	}
	return allowed
}

func (p *FilePolicy) ValidatePath(path string) error {
	for _, r := range p.Rules {
		if r.Type == "path" {
			for _, pattern := range r.Values {
				match, _ := regexp.MatchString(pattern, path)
				if match {
					if r.Action == "deny" {
						return &ErrPolicyViolation{Reason: "path access explicitly denied by policy", Path: path}
					}
				}
			}
		}
	}
	return nil
}

func (p *FilePolicy) ValidateWormholeURL(u string, allowed []string) error {
	for _, r := range p.Rules {
		if r.Type == "url" {
			for _, pattern := range r.Values {
				match, _ := regexp.MatchString(pattern, u)
				if match {
					if r.Action == "deny" {
						return &ErrPolicyViolation{Reason: "URL access explicitly denied by policy"}
					}
				}
			}
		}
	}
	return nil
}

func (p *FilePolicy) ValidateTunnel(insecure bool) error {
	if insecure {
		// File policies default to prohibiting insecure tunnels for safety
		return &ErrPolicyViolation{Reason: "unverified/insecure tunnels are prohibited by file policy"}
	}
	return nil
}

func (p *FilePolicy) ValidateProfile(id byte) error {
	// If a policy defines 'allowed_profiles', enforce it
	for _, r := range p.Rules {
		if r.Type == "profile" {
			found := false
			for _, v := range r.Values {
				if v == fmt.Sprintf("%d", id) {
					found = true
					break
				}
			}
			if r.Action == "allow" && !found {
				return &ErrPolicyViolation{Reason: fmt.Sprintf("cryptographic profile %d is not permitted by policy", id)}
			}
			if r.Action == "deny" && found {
				return &ErrPolicyViolation{Reason: fmt.Sprintf("cryptographic profile %d is explicitly denied by policy", id)}
			}
		}
	}
	return nil
}

func (p *FilePolicy) ClampConcurrency(req, max int) int {
	if p.Limits.MaxThreads > 0 && req > int(p.Limits.MaxThreads) {
		return int(p.Limits.MaxThreads)
	}
	return req
}

func (p *FilePolicy) ClampProfileGeneration(t, m uint32, th uint8) (uint32, uint32, uint8) {
	if p.Limits.MaxTime > 0 && t > p.Limits.MaxTime {
		t = p.Limits.MaxTime
	}
	if p.Limits.MaxMemoryKB > 0 && m > p.Limits.MaxMemoryKB {
		m = p.Limits.MaxMemoryKB
	}
	if p.Limits.MaxThreads > 0 && th > p.Limits.MaxThreads {
		th = p.Limits.MaxThreads
	}
	return t, m, th
}

func (p *FilePolicy) ValidateProfileResource(m, t uint32, th uint8, l AgentLimitsConfig) error {
	if p.Limits.MaxMemoryKB > 0 && m > p.Limits.MaxMemoryKB {
		return &ErrPolicyViolation{Reason: fmt.Sprintf("memory exceeds policy limit (%d KB)", p.Limits.MaxMemoryKB)}
	}
	if p.Limits.MaxTime > 0 && t > p.Limits.MaxTime {
		return &ErrPolicyViolation{Reason: fmt.Sprintf("time iterations exceed policy limit (%d)", p.Limits.MaxTime)}
	}
	return nil
}

func (p *FilePolicy) AllowConfigModification() bool {
	return p.HasCapability(CapConfig)
}

func (p *FilePolicy) IsAgent() bool {
	// A file policy is considered "Agent-like" if it restricts standard human capabilities
	return !p.HasCapability(CapVaultDelete)
}

// LoadPolicyFromFile reads a JSON policy file and returns a SecurityPolicy.
func LoadPolicyFromFile(path string) (SecurityPolicy, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return LoadPolicyFromBytes(data)
}

// LoadPolicyFromBytes parses JSON data into a FilePolicy.
func LoadPolicyFromBytes(data []byte) (SecurityPolicy, error) {
	var p FilePolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse policy JSON: %w", err)
	}
	return &p, nil
}
