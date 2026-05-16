package crypto

import (
	"testing"
)

func TestPolicyLogicRegression(t *testing.T) {
	// Test CompositePolicy "Explicit-Allow-OR" logic for Quorum approvals
	t.Run("CompositePolicy_AutoQuorum_OR_Logic", func(t *testing.T) {
		// Base policies that DENY auto-quorum
		human := &HumanPolicy{} // AllowAutoQuorum always false
		agent := &AgentPolicy{} // AllowAutoQuorum always false

		// File policy that ALLOWS auto-quorum for a specific ID
		filePolicy := &FilePolicy{
			PolicyName: "auto-approve-initiator",
			Rules: []PolicyRule{
				{
					Type:   "quorum",
					Action: "vault_unlock",
					Values: []string{"auto-approve:@initiator"},
				},
			},
		}

		composite := &CompositePolicy{
			Policies: []SecurityPolicy{human, filePolicy},
		}

		// It should ALLOW because filePolicy allows it (OR logic)
		if !composite.AllowAutoQuorum("@initiator", "vault_unlock") {
			t.Error("expected composite policy to ALLOW auto-quorum via FilePolicy override")
		}

		compositeAgent := &CompositePolicy{
			Policies: []SecurityPolicy{agent, filePolicy},
		}
		if !compositeAgent.AllowAutoQuorum("@initiator", "vault_unlock") {
			t.Error("expected composite agent policy to ALLOW auto-quorum via FilePolicy override")
		}
	})

	t.Run("CompositePolicy_Capability_AND_Logic", func(t *testing.T) {
		// Human policy ALLOWS everything
		human := &HumanPolicy{}

		// File policy DENIES identity
		filePolicy := &FilePolicy{
			PolicyName: "no-identity",
			Rules: []PolicyRule{
				{
					Type:   "capability",
					Action: "deny",
					Values: []string{"identity"},
				},
			},
		}

		composite := &CompositePolicy{
			Policies: []SecurityPolicy{human, filePolicy},
		}

		// It should DENY because filePolicy denies it (AND logic / Strictest-Wins)
		if composite.HasCapability(CapIdentity) {
			t.Error("expected composite policy to DENY identity capability via FilePolicy")
		}
	})
}
