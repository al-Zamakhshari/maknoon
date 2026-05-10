package crypto

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockQuorumPolicy struct {
	HumanPolicy
	threshold int
}

func (p *mockQuorumPolicy) QuorumRequirement(action string) (int, []string) {
	if action == string(ActionConfigAdmin) {
		return p.threshold, []string{"peer1", "peer2"}
	}
	return 0, nil
}

func TestEngine_UpdateConfig_Quorum(t *testing.T) {
	tmpDir := t.TempDir()
	conf := DefaultConfig()
	conf.Paths.VaultsDir = tmpDir
	conf.Paths.KeysDir = tmpDir

	policy := &mockQuorumPolicy{threshold: 2}

	// Create a dummy identity for the engine to use for signing
	idMgr := NewIdentityManager()
	idMgr.Config = conf

	eng, err := NewEngine(policy, idMgr, conf, nil, slog.Default())
	assert.NoError(t, err)
	defer eng.Close()

	ectx := &EngineContext{
		Context: context.Background(),
		Policy:  policy,
	}

	newConf := DefaultConfig()
	newConf.Security.ArgonTime = 5

	// Attempting UpdateConfig should now reach the QuorumRequest but fail
	// because there are no peers/responses, or fail earlier due to missing signing keys.
	err = eng.UpdateConfig(ectx, newConf)
	assert.Error(t, err)
	// The error might be about missing keys or quorum failure.
	// Since we haven't loaded keys, it likely fails on signing.
	assert.Contains(t, err.Error(), "administrative quorum request failed")
}
