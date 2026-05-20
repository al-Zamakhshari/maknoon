package crypto

import "testing"

// --- HumanPolicy ---

func TestHumanPolicyName(t *testing.T) {
	p := &HumanPolicy{}
	if p.Name() != "human" {
		t.Errorf("Name() = %q, want %q", p.Name(), "human")
	}
}

func TestHumanPolicyAllowsAll(t *testing.T) {
	p := &HumanPolicy{}
	for _, cap := range []Capability{CapProtect, CapUnprotect, CapVaultRead, CapVaultWrite, CapVaultDelete, CapIdentity, CapConfig} {
		if !p.HasCapability(cap) {
			t.Errorf("HumanPolicy should allow %s", cap)
		}
	}
}

func TestHumanPolicyValidatePath(t *testing.T) {
	p := &HumanPolicy{}
	if err := p.ValidatePath("/any/path"); err != nil {
		t.Errorf("HumanPolicy.ValidatePath should always pass: %v", err)
	}
}

func TestHumanPolicyValidateWormholeURL(t *testing.T) {
	p := &HumanPolicy{}
	if err := p.ValidateWormholeURL("wss://example.com", nil); err != nil {
		t.Errorf("HumanPolicy.ValidateWormholeURL should always pass: %v", err)
	}
}

func TestHumanPolicyValidateTunnel(t *testing.T) {
	p := &HumanPolicy{}
	if err := p.ValidateTunnel(true); err != nil {
		t.Errorf("HumanPolicy.ValidateTunnel(insecure) should pass: %v", err)
	}
}

func TestHumanPolicyClampConcurrency(t *testing.T) {
	p := &HumanPolicy{}
	if got := p.ClampConcurrency(4, 8); got != 4 {
		t.Errorf("ClampConcurrency(4, 8) = %d, want 4", got)
	}
	if got := p.ClampConcurrency(16, 8); got != 16 {
		t.Errorf("HumanPolicy should not clamp: got %d", got)
	}
}

func TestHumanPolicyMeta(t *testing.T) {
	p := &HumanPolicy{}
	if !p.AllowConfigModification() {
		t.Error("HumanPolicy should allow config modification")
	}
	if p.IsAgent() {
		t.Error("HumanPolicy.IsAgent() should be false")
	}
	if p.AllowAutoQuorum("op", "approve") {
		t.Error("HumanPolicy.AllowAutoQuorum should return false")
	}
	thresh, peers := p.QuorumRequirement("sign")
	if thresh != 0 || len(peers) != 0 {
		t.Errorf("HumanPolicy.QuorumRequirement: thresh=%d peers=%v", thresh, peers)
	}
}

// --- AgentPolicy ---

func TestAgentPolicyName(t *testing.T) {
	p := &AgentPolicy{}
	if p.Name() != "agent" {
		t.Errorf("Name() = %q, want %q", p.Name(), "agent")
	}
}

func TestAgentPolicyBlocksVaultDelete(t *testing.T) {
	p := &AgentPolicy{}
	if p.HasCapability(CapVaultDelete) {
		t.Error("AgentPolicy must block CapVaultDelete")
	}
	// All other capabilities should be allowed.
	for _, cap := range []Capability{CapProtect, CapUnprotect, CapVaultRead, CapVaultWrite, CapIdentity, CapConfig} {
		if !p.HasCapability(cap) {
			t.Errorf("AgentPolicy should allow %s", cap)
		}
	}
}

func TestAgentPolicyValidatePath(t *testing.T) {
	p := &AgentPolicy{}
	// Empty and "-" always pass.
	if err := p.ValidatePath(""); err != nil {
		t.Errorf("empty path: %v", err)
	}
	if err := p.ValidatePath("-"); err != nil {
		t.Errorf("dash path: %v", err)
	}
}

func TestAgentPolicyValidateWormholeURL(t *testing.T) {
	p := &AgentPolicy{}
	// Empty URL is allowed.
	if err := p.ValidateWormholeURL("", nil); err != nil {
		t.Errorf("empty URL should pass: %v", err)
	}
	// URL in allowlist passes.
	if err := p.ValidateWormholeURL("wss://ok.example.com", []string{"wss://ok.example.com"}); err != nil {
		t.Errorf("allowed URL should pass: %v", err)
	}
	// URL not in allowlist is blocked.
	if err := p.ValidateWormholeURL("wss://evil.example.com", []string{"wss://ok.example.com"}); err == nil {
		t.Error("unlisted URL should be blocked")
	}
}

func TestAgentPolicyValidateTunnel(t *testing.T) {
	p := &AgentPolicy{}
	if err := p.ValidateTunnel(true); err == nil {
		t.Error("AgentPolicy should block insecure tunnels")
	}
	if err := p.ValidateTunnel(false); err != nil {
		t.Errorf("AgentPolicy should allow secure tunnels: %v", err)
	}
}

func TestAgentPolicyClampConcurrency(t *testing.T) {
	p := &AgentPolicy{}
	// Exceeds max → clamped.
	if got := p.ClampConcurrency(16, 8); got != 8 {
		t.Errorf("ClampConcurrency(16, 8) = %d, want 8", got)
	}
	// Within max → unchanged.
	if got := p.ClampConcurrency(4, 8); got != 4 {
		t.Errorf("ClampConcurrency(4, 8) = %d, want 4", got)
	}
	// Zero → max.
	if got := p.ClampConcurrency(0, 8); got != 8 {
		t.Errorf("ClampConcurrency(0, 8) = %d, want 8", got)
	}
}

func TestAgentPolicyValidateProfileResource(t *testing.T) {
	p := &AgentPolicy{}
	limits := AgentLimitsConfig{MaxMemoryKB: 1024, MaxTime: 5, MaxThreads: 4}

	if err := p.ValidateProfileResource(512, 3, 2, limits); err != nil {
		t.Errorf("within limits: %v", err)
	}
	if err := p.ValidateProfileResource(2048, 3, 2, limits); err == nil {
		t.Error("memory over limit should fail")
	}
	if err := p.ValidateProfileResource(512, 10, 2, limits); err == nil {
		t.Error("time over limit should fail")
	}
	if err := p.ValidateProfileResource(512, 3, 8, limits); err == nil {
		t.Error("threads over limit should fail")
	}
}

func TestAgentPolicyMeta(t *testing.T) {
	p := &AgentPolicy{}
	if !p.AllowConfigModification() {
		t.Error("AgentPolicy.AllowConfigModification should return true")
	}
	if !p.IsAgent() {
		t.Error("AgentPolicy.IsAgent() should be true")
	}
	if p.AllowAutoQuorum("op", "approve") {
		t.Error("AgentPolicy.AllowAutoQuorum should return false by default")
	}
	thresh, peers := p.QuorumRequirement("sign")
	if thresh != 0 || len(peers) != 0 {
		t.Errorf("AgentPolicy.QuorumRequirement: thresh=%d peers=%v", thresh, peers)
	}
}

// --- ValidatePath (package-level) ---

func TestValidatePathAllowedPaths(t *testing.T) {
	// "-" and "" always pass regardless of restricted mode.
	for _, restricted := range []bool{true, false} {
		if err := ValidatePath("-", restricted); err != nil {
			t.Errorf("ValidatePath('-', %v): %v", restricted, err)
		}
		if err := ValidatePath("", restricted); err != nil {
			t.Errorf("ValidatePath('', %v): %v", restricted, err)
		}
	}
}
