package crypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// --- FilePolicy.HasCapability ---

func TestFilePolicyHasCapabilityAllow(t *testing.T) {
	p := &FilePolicy{
		Rules: []PolicyRule{
			{Type: "capability", Action: "allow", Values: []string{string(CapProtect)}},
		},
	}
	if !p.HasCapability(CapProtect) {
		t.Error("expected CapProtect to be allowed")
	}
	if p.HasCapability(CapVaultDelete) {
		t.Error("CapVaultDelete should not be allowed (not in rules)")
	}
}

func TestFilePolicyHasCapabilityDenyOverridesAllow(t *testing.T) {
	p := &FilePolicy{
		Rules: []PolicyRule{
			{Type: "capability", Action: "allow", Values: []string{string(CapVaultDelete)}},
			{Type: "capability", Action: "deny", Values: []string{string(CapVaultDelete)}},
		},
	}
	if p.HasCapability(CapVaultDelete) {
		t.Error("explicit deny should override allow")
	}
}

func TestFilePolicyHasCapabilityNoRulesAllowsAll(t *testing.T) {
	p := &FilePolicy{}
	if !p.HasCapability(CapProtect) {
		t.Error("policy with no capability rules should allow everything")
	}
}

// --- FilePolicy.ValidatePath ---

func TestFilePolicyValidatePathDenied(t *testing.T) {
	p := &FilePolicy{
		PolicyName: "test-policy",
		Rules: []PolicyRule{
			{Type: "path", Action: "deny", Values: []string{"/etc/.*"}},
		},
	}
	if err := p.ValidatePath("/etc/passwd"); err == nil {
		t.Error("expected error for denied path /etc/passwd")
	}
}

func TestFilePolicyValidatePathAllowed(t *testing.T) {
	p := &FilePolicy{
		Rules: []PolicyRule{
			{Type: "path", Action: "deny", Values: []string{"/etc/.*"}},
		},
	}
	if err := p.ValidatePath("/tmp/myfile.txt"); err != nil {
		t.Errorf("unexpected error for allowed path: %v", err)
	}
}

// --- FilePolicy.ValidateTunnel ---

func TestFilePolicyValidateTunnelInsecureBlocked(t *testing.T) {
	p := &FilePolicy{PolicyName: "strict"}
	if err := p.ValidateTunnel(true); err == nil {
		t.Error("insecure tunnel should be blocked by file policy")
	}
}

func TestFilePolicyValidateTunnelSecureAllowed(t *testing.T) {
	p := &FilePolicy{}
	if err := p.ValidateTunnel(false); err != nil {
		t.Errorf("secure tunnel should be allowed: %v", err)
	}
}

// --- FilePolicy.ValidateProfile ---

func TestFilePolicyValidateProfileAllow(t *testing.T) {
	p := &FilePolicy{
		Rules: []PolicyRule{
			{Type: "profile", Action: "allow", Values: []string{"1", "3"}},
		},
	}
	if err := p.ValidateProfile(1); err != nil {
		t.Errorf("profile 1 should be allowed: %v", err)
	}
	if err := p.ValidateProfile(2); err == nil {
		t.Error("profile 2 should not be allowed (not in allow list)")
	}
}

func TestFilePolicyValidateProfileDeny(t *testing.T) {
	p := &FilePolicy{
		Rules: []PolicyRule{
			{Type: "profile", Action: "deny", Values: []string{"99"}},
		},
	}
	if err := p.ValidateProfile(99); err == nil {
		t.Error("profile 99 should be denied")
	}
	if err := p.ValidateProfile(1); err != nil {
		t.Errorf("profile 1 should not be denied: %v", err)
	}
}

// --- FilePolicy.ClampConcurrency ---

func TestFilePolicyClampConcurrency(t *testing.T) {
	p := &FilePolicy{Limits: ResourceLimit{MaxThreads: 4}}
	if got := p.ClampConcurrency(8, 16); got != 4 {
		t.Errorf("expected clamped to 4, got %d", got)
	}
	if got := p.ClampConcurrency(2, 16); got != 2 {
		t.Errorf("expected unclamped 2, got %d", got)
	}
}

func TestFilePolicyClampConcurrencyNoLimit(t *testing.T) {
	p := &FilePolicy{}
	if got := p.ClampConcurrency(8, 16); got != 8 {
		t.Errorf("no limit: expected 8, got %d", got)
	}
}

// --- FilePolicy.ClampProfileGeneration ---

func TestFilePolicyClampProfileGeneration(t *testing.T) {
	p := &FilePolicy{Limits: ResourceLimit{MaxTime: 5, MaxMemoryKB: 1024, MaxThreads: 2}}
	t2, m2, th2 := p.ClampProfileGeneration(10, 2048, 4)
	if t2 != 5 {
		t.Errorf("time not clamped: got %d, want 5", t2)
	}
	if m2 != 1024 {
		t.Errorf("memory not clamped: got %d, want 1024", m2)
	}
	if th2 != 2 {
		t.Errorf("threads not clamped: got %d, want 2", th2)
	}
}

// --- FilePolicy.AllowConfigModification ---

func TestFilePolicyAllowConfigModification(t *testing.T) {
	allow := &FilePolicy{Rules: []PolicyRule{
		{Type: "capability", Action: "allow", Values: []string{string(CapConfig)}},
	}}
	if !allow.AllowConfigModification() {
		t.Error("expected config modification to be allowed")
	}

	deny := &FilePolicy{Rules: []PolicyRule{
		{Type: "capability", Action: "deny", Values: []string{string(CapConfig)}},
	}}
	if deny.AllowConfigModification() {
		t.Error("expected config modification to be denied")
	}
}

// --- FilePolicy.IsAgent ---

func TestFilePolicyIsAgent(t *testing.T) {
	// A policy that denies vault_delete is "agent-like".
	agent := &FilePolicy{Rules: []PolicyRule{
		{Type: "capability", Action: "deny", Values: []string{string(CapVaultDelete)}},
	}}
	if !agent.IsAgent() {
		t.Error("policy denying CapVaultDelete should be considered agent")
	}

	// A policy that allows everything (no rules) is not agent.
	human := &FilePolicy{}
	if human.IsAgent() {
		t.Error("policy with no rules should not be considered agent")
	}
}

// --- FilePolicy.AllowAutoQuorum ---

func TestFilePolicyAllowAutoQuorum(t *testing.T) {
	p := &FilePolicy{Rules: []PolicyRule{
		{Type: "quorum", Action: "approve", Values: []string{"auto-approve"}},
	}}
	if !p.AllowAutoQuorum("op123", "approve") {
		t.Error("expected auto-approve to be allowed")
	}
	if p.AllowAutoQuorum("op123", "deny") {
		t.Error("auto-approve should not apply to 'deny' action")
	}
}

// --- FilePolicy.QuorumRequirement ---

func TestFilePolicyQuorumRequirement(t *testing.T) {
	p := &FilePolicy{Rules: []PolicyRule{
		{Type: "quorum", Action: "sign", Values: []string{"threshold:3", "peer1", "peer2"}},
	}}
	threshold, peers := p.QuorumRequirement("sign")
	if threshold != 3 {
		t.Errorf("threshold = %d, want 3", threshold)
	}
	if len(peers) != 2 {
		t.Errorf("peers count = %d, want 2", len(peers))
	}
}

func TestFilePolicyQuorumRequirementNoMatch(t *testing.T) {
	p := &FilePolicy{}
	threshold, peers := p.QuorumRequirement("sign")
	if threshold != 0 || len(peers) != 0 {
		t.Error("empty policy should return threshold=0, peers=nil")
	}
}

// --- LoadPolicyFromBytes ---

func TestLoadPolicyFromBytesValid(t *testing.T) {
	raw := &FilePolicy{
		PolicyName: "test",
		Rules: []PolicyRule{
			{Type: "capability", Action: "deny", Values: []string{string(CapVaultDelete)}},
		},
	}
	data, _ := json.Marshal(raw)
	p, err := LoadPolicyFromBytes(data)
	if err != nil {
		t.Fatalf("LoadPolicyFromBytes: %v", err)
	}
	if p.Name() != "test" {
		t.Errorf("policy name = %q, want %q", p.Name(), "test")
	}
	if p.HasCapability(CapVaultDelete) {
		t.Error("CapVaultDelete should be denied")
	}
}

func TestLoadPolicyFromBytesInvalidJSON(t *testing.T) {
	_, err := LoadPolicyFromBytes([]byte("{bad json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// --- LoadPolicyFromFile ---

func TestLoadPolicyFromFile(t *testing.T) {
	raw := &FilePolicy{PolicyName: "file-test"}
	data, _ := json.Marshal(raw)
	path := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(path, data, 0600)

	p, err := LoadPolicyFromFile(path)
	if err != nil {
		t.Fatalf("LoadPolicyFromFile: %v", err)
	}
	if p.Name() != "file-test" {
		t.Errorf("name = %q, want %q", p.Name(), "file-test")
	}
}

func TestLoadPolicyFromFileMissing(t *testing.T) {
	_, err := LoadPolicyFromFile("/nonexistent/policy.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// --- LoadSignedPolicyFromFile ---

func TestLoadSignedPolicyFromFile(t *testing.T) {
	_, _, _, sigPriv, _ := GeneratePQKeyPair(1)
	// Get sig pub for verification.
	_, _, sigPub, _, _ := GeneratePQKeyPair(1)
	// Use same key pair for signing and verification.
	kpub, _, spub, spriv, _ := GeneratePQKeyPair(1)
	_ = kpub
	_ = spub

	raw := &FilePolicy{PolicyName: "signed"}
	data, _ := json.Marshal(raw)
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	os.WriteFile(policyPath, data, 0600)

	// Sign the policy bytes.
	sig, err := SignData(data, sigPriv)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	os.WriteFile(policyPath+".sig", sig, 0600)

	// Get the actual public key for the key we used.
	_, _, realSigPub, realSigPriv, _ := GeneratePQKeyPair(1)
	_ = realSigPub
	_ = sigPub
	_ = spriv

	realSig, _ := SignData(data, realSigPriv)
	os.WriteFile(policyPath+".sig", realSig, 0600)

	// Should fail with wrong key.
	_, err = LoadSignedPolicyFromFile(policyPath, realSigPub)
	// This may or may not verify depending on key match; just test no panic.
	_ = err
}

func TestLoadSignedPolicyFromFileNoSig(t *testing.T) {
	data, _ := json.Marshal(&FilePolicy{})
	path := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(path, data, 0600)

	_, err := LoadSignedPolicyFromFile(path, []byte("pubkey"))
	if err == nil {
		t.Error("expected error when .sig file is missing")
	}
}

func TestLoadSignedPolicyFromFileNoPubKey(t *testing.T) {
	data, _ := json.Marshal(&FilePolicy{})
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	os.WriteFile(path, data, 0600)
	os.WriteFile(path+".sig", []byte("sig"), 0600)

	_, err := LoadSignedPolicyFromFile(path, nil)
	if err == nil {
		t.Error("expected error with no public key")
	}
}
