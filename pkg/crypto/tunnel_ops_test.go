package crypto

import (
	"context"
	"testing"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTunnelEngineOperations(t *testing.T) {
	cfg := DefaultConfig()
	policy := &HumanPolicy{}

	engine, err := NewEngine(policy, nil, cfg, nil, nil)
	require.NoError(t, err)
	defer engine.Close()

	ctx := context.Background()
	ectx := &EngineContext{Context: ctx, Policy: policy}

	t.Run("TunnelStatusEmpty", func(t *testing.T) {
		status, err := engine.TunnelStatus(ectx)
		require.NoError(t, err)
		assert.False(t, status.Active)
	})

	t.Run("TunnelStopEmpty", func(t *testing.T) {
		err := engine.TunnelStop(ectx)
		assert.NoError(t, err)
	})

	t.Run("TunnelStartFailureInvalidAddr", func(t *testing.T) {
		opts := tunnel.TunnelOptions{
			RemoteEndpoint: "invalid-addr",
		}
		_, err := engine.TunnelStart(ectx, opts)
		assert.Error(t, err)
	})
}
