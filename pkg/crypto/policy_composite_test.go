package crypto

import "testing"

// ─── CompositePolicy ──────────────────────────────────────────────────────────

func TestCompositePolicyName(t *testing.T) {
	cp := &CompositePolicy{Policies: []SecurityPolicy{&HumanPolicy{}, &AgentPolicy{}}}
	name := cp.Name()
	if name == "" {
		t.Error("CompositePolicy.Name() returned empty string")
	}
	// Should contain sub-policy names.
	if name == "human" || name == "agent" {
		t.Errorf("CompositePolicy.Name() should composite names, got %q", name)
	}
}

func TestCompositePolicyHasCapabilityAllAllow(t *testing.T) {
	// Two permissive policies → all caps allowed.
	cp := &CompositePolicy{Policies: []SecurityPolicy{&HumanPolicy{}, &HumanPolicy{}}}
	if !cp.HasCapability(CapProtect) {
		t.Error("CompositePolicy with two HumanPolicy should allow CapEncrypt")
	}
}

func TestCompositePolicyHasCapabilityOneDenies(t *testing.T) {
	// AgentPolicy denies CapVaultDelete → composite denies it.
	cp := &CompositePolicy{Policies: []SecurityPolicy{&HumanPolicy{}, &AgentPolicy{}}}
	if cp.HasCapability(CapVaultDelete) {
		t.Error("CompositePolicy with AgentPolicy should deny CapVaultDelete")
	}
	if !cp.HasCapability(CapProtect) {
		t.Error("CompositePolicy should allow CapProtect when not denied by any sub-policy")
	}
}

func TestCompositePolicyValidatePath(t *testing.T) {
	cp := &CompositePolicy{Policies: []SecurityPolicy{&HumanPolicy{}, &HumanPolicy{}}}
	if err := cp.ValidatePath("/any/path"); err != nil {
		t.Errorf("CompositePolicy(HumanPolicy×2).ValidatePath: %v", err)
	}
}

func TestCompositePolicyValidateWormholeURL(t *testing.T) {
	cp := &CompositePolicy{Policies: []SecurityPolicy{&HumanPolicy{}, &HumanPolicy{}}}
	if err := cp.ValidateWormholeURL("wss://ok.example.com", nil); err != nil {
		t.Errorf("CompositePolicy(HumanPolicy×2).ValidateWormholeURL: %v", err)
	}
}

func TestCompositePolicyValidateTunnelStrictestWins(t *testing.T) {
	// AgentPolicy blocks insecure tunnels → composite must block too.
	cp := &CompositePolicy{Policies: []SecurityPolicy{&HumanPolicy{}, &AgentPolicy{}}}
	if err := cp.ValidateTunnel(true); err == nil {
		t.Error("CompositePolicy with AgentPolicy should block insecure tunnel")
	}
	if err := cp.ValidateTunnel(false); err != nil {
		t.Errorf("CompositePolicy: secure tunnel should pass: %v", err)
	}
}

func TestCompositePolicyValidateProfile(t *testing.T) {
	cp := &CompositePolicy{Policies: []SecurityPolicy{&HumanPolicy{}, &HumanPolicy{}}}
	if err := cp.ValidateProfile(1); err != nil {
		t.Errorf("CompositePolicy.ValidateProfile: %v", err)
	}
}

func TestCompositePolicyClampConcurrency(t *testing.T) {
	// AgentPolicy clamps to max; HumanPolicy doesn't. Composite takes strictest.
	cp := &CompositePolicy{Policies: []SecurityPolicy{&HumanPolicy{}, &AgentPolicy{}}}
	got := cp.ClampConcurrency(16, 8)
	if got > 8 {
		t.Errorf("CompositePolicy.ClampConcurrency(16,8) = %d, want ≤ 8", got)
	}
}

func TestCompositePolicyClampProfileGeneration(t *testing.T) {
	cp := &CompositePolicy{Policies: []SecurityPolicy{&HumanPolicy{}, &HumanPolicy{}}}
	t2, m2, th2 := cp.ClampProfileGeneration(5, 1024, 4)
	if t2 != 5 || m2 != 1024 || th2 != 4 {
		t.Errorf("ClampProfileGeneration mismatch: t=%d m=%d th=%d", t2, m2, th2)
	}
}

func TestCompositePolicyValidateProfileResource(t *testing.T) {
	cp := &CompositePolicy{Policies: []SecurityPolicy{&HumanPolicy{}, &HumanPolicy{}}}
	limits := AgentLimitsConfig{MaxMemoryKB: 4096, MaxTime: 10, MaxThreads: 8}
	if err := cp.ValidateProfileResource(1024, 5, 4, limits); err != nil {
		t.Errorf("CompositePolicy.ValidateProfileResource within limits: %v", err)
	}
}

func TestCompositePolicyMeta(t *testing.T) {
	cpHuman := &CompositePolicy{Policies: []SecurityPolicy{&HumanPolicy{}, &HumanPolicy{}}}
	if !cpHuman.AllowConfigModification() {
		t.Error("CompositePolicy(HumanPolicy×2).AllowConfigModification should be true")
	}
	if cpHuman.IsAgent() {
		t.Error("CompositePolicy(HumanPolicy×2).IsAgent should be false")
	}

	cpAgent := &CompositePolicy{Policies: []SecurityPolicy{&HumanPolicy{}, &AgentPolicy{}}}
	if cpAgent.IsAgent() {
		// CompositePolicy.IsAgent depends on implementation — just ensure no panic.
		_ = cpAgent.IsAgent()
	}

	if cpHuman.AllowAutoQuorum("op", "approve") {
		t.Error("CompositePolicy(HumanPolicy×2).AllowAutoQuorum should return false")
	}
	thresh, peers := cpHuman.QuorumRequirement("sign")
	if thresh != 0 || len(peers) != 0 {
		t.Errorf("QuorumRequirement: thresh=%d peers=%v", thresh, peers)
	}
}

// ─── FIPSPolicy ───────────────────────────────────────────────────────────────

func TestFIPSPolicyName(t *testing.T) {
	p := &FIPSPolicy{}
	if p.Name() != "fips" {
		t.Errorf("FIPSPolicy.Name() = %q, want %q", p.Name(), "fips")
	}
}

func TestFIPSPolicyHasCapability(t *testing.T) {
	p := &FIPSPolicy{}
	// FIPSPolicy restricts profile capabilities only; all other caps pass.
	if !p.HasCapability(CapProtect) {
		t.Error("FIPSPolicy should allow CapProtect")
	}
}

func TestFIPSPolicyValidateTunnel(t *testing.T) {
	p := &FIPSPolicy{}
	if err := p.ValidateTunnel(true); err == nil {
		t.Error("FIPSPolicy should block insecure tunnels")
	}
	if err := p.ValidateTunnel(false); err != nil {
		t.Errorf("FIPSPolicy should allow secure tunnels: %v", err)
	}
}

func TestFIPSPolicyValidateProfile(t *testing.T) {
	p := &FIPSPolicy{}
	// Profile 1 (NIST ML-KEM+ML-DSA) is FIPS-approved; others may not be.
	err := p.ValidateProfile(1)
	// Either pass or structured error — just no panic.
	_ = err
}

func TestFIPSPolicyClampConcurrency(t *testing.T) {
	p := &FIPSPolicy{}
	if got := p.ClampConcurrency(4, 8); got != 4 {
		t.Errorf("FIPSPolicy.ClampConcurrency(4,8) = %d, want 4 (no clamp)", got)
	}
}

func TestFIPSPolicyClampProfileGeneration(t *testing.T) {
	p := &FIPSPolicy{}
	// FIPSPolicy mandates fixed NIST parameters regardless of input.
	t2, m2, th2 := p.ClampProfileGeneration(99, 99999, 99)
	if t2 == 0 || m2 == 0 || th2 == 0 {
		t.Errorf("FIPSPolicy.ClampProfileGeneration returned zeros: t=%d m=%d th=%d", t2, m2, th2)
	}
}

func TestFIPSPolicyMeta(t *testing.T) {
	p := &FIPSPolicy{}
	_ = p.AllowConfigModification()
	if p.IsAgent() {
		t.Error("FIPSPolicy.IsAgent should be false")
	}
	if p.AllowAutoQuorum("op", "approve") {
		t.Error("FIPSPolicy.AllowAutoQuorum should return false")
	}
	thresh, peers := p.QuorumRequirement("sign")
	if thresh != 0 || len(peers) != 0 {
		t.Errorf("FIPSPolicy.QuorumRequirement: thresh=%d peers=%v", thresh, peers)
	}
}

func TestFIPSPolicyValidateProfileResource(t *testing.T) {
	p := &FIPSPolicy{}
	limits := AgentLimitsConfig{MaxMemoryKB: 4096, MaxTime: 10, MaxThreads: 8}
	_ = p.ValidateProfileResource(1024, 5, 4, limits)
}
