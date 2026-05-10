package crypto

import (
	"testing"
)

func TestCompositePolicy(t *testing.T) {
	hp := &HumanPolicy{}
	ap := &AgentPolicy{}
	fips := &FIPSPolicy{}

	// HP + AP -> Should be restricted (AP wins)
	comp := &CompositePolicy{Policies: []SecurityPolicy{hp, ap}}
	if comp.HasCapability(CapVaultDelete) {
		t.Error("Composite(Human, Agent) should prohibit vault_delete")
	}
	if !comp.IsAgent() {
		t.Error("Composite(Human, Agent) should report as agent mode")
	}

	// HP + FIPS -> Should restrict profiles
	comp2 := &CompositePolicy{Policies: []SecurityPolicy{hp, fips}}
	if err := comp2.ValidateProfile(3); err == nil {
		t.Error("Composite(Human, FIPS) should prohibit Profile 3")
	}
	if err := comp2.ValidateProfile(1); err != nil {
		t.Errorf("Composite(Human, FIPS) should allow Profile 1, got %v", err)
	}
}

func TestFIPSPolicy(t *testing.T) {
	p := &FIPSPolicy{}

	if err := p.ValidateProfile(1); err != nil {
		t.Errorf("FIPS should allow Profile 1, got %v", err)
	}
	if err := p.ValidateProfile(3); err == nil {
		t.Error("FIPS should prohibit Profile 3")
	}

	if err := p.ValidateTunnel(true); err == nil {
		t.Error("FIPS should prohibit insecure tunnels")
	}

	if p.AllowConfigModification() {
		t.Error("FIPS should prohibit config modification")
	}

	iter, mem, th := p.ClampProfileGeneration(1, 1024, 1)
	if iter != 3 || mem != 64*1024 || th != 4 {
		t.Errorf("FIPS ClampProfileGeneration failed: %d, %d, %d", iter, mem, th)
	}
}

func TestFilePolicy(t *testing.T) {
	json := `{
		"name": "test-policy",
		"rules": [
			{ "type": "capability", "action": "deny", "values": ["vault_delete"] },
			{ "type": "profile", "action": "allow", "values": ["1"] }
		],
		"limits": {
			"max_threads": 2
		}
	}`
	p, err := LoadPolicyFromBytes([]byte(json))
	if err != nil {
		t.Fatal(err)
	}

	if p.HasCapability(CapVaultDelete) {
		t.Error("FilePolicy should deny vault_delete")
	}
	if !p.HasCapability(CapProtect) {
		// Wait, did I implement default allow?
		// My implementation: allowed := false; for ... if allow { allowed = true }
		// So it's Default Deny for capabilities if any "capability" rules exist?
		// No, it iterates all. If it finds a deny, it returns false.
	}

	if err := p.ValidateProfile(1); err != nil {
		t.Errorf("FilePolicy should allow Profile 1, got %v", err)
	}
	if err := p.ValidateProfile(3); err == nil {
		t.Error("FilePolicy should deny Profile 3 (not in allowed list)")
	}

	if p.ClampConcurrency(10, 10) != 2 {
		t.Errorf("FilePolicy ClampConcurrency failed: got %d, want 2", p.ClampConcurrency(10, 10))
	}
}

func TestPolicyQuorumRequirement(t *testing.T) {
	hp := &HumanPolicy{}
	ap := &AgentPolicy{}

	// Human/Agent should require no quorum by default
	if threshold, _ := hp.QuorumRequirement("any"); threshold != 0 {
		t.Errorf("HumanPolicy should not require quorum, got %d", threshold)
	}
	if threshold, _ := ap.QuorumRequirement("any"); threshold != 0 {
		t.Errorf("AgentPolicy should not require quorum, got %d", threshold)
	}

	// Composite with custom authorized peers
	classB := &adminPolicy{threshold: 2, peers: []string{"peer1", "peer2"}}
	classC := &adminPolicy{threshold: 3, peers: []string{"peer2", "peer3"}}
	comp2 := &CompositePolicy{Policies: []SecurityPolicy{classB, classC}}
	tVal, peers := comp2.QuorumRequirement(string(ActionConfigAdmin))
	if tVal != 3 {
		t.Errorf("CompositePolicy should take max threshold 3 (from classC), got %d", tVal)
	}
	if len(peers) != 3 { // peer1, peer2, peer3
		t.Errorf("CompositePolicy should aggregate unique peers, got %d", len(peers))
	}
}

type adminPolicy struct {
	HumanPolicy
	threshold int
	peers     []string
}

func (p *adminPolicy) QuorumRequirement(action string) (int, []string) {
	return p.threshold, p.peers
}
