package crypto

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKMSOperations(t *testing.T) {
	cfg := DefaultConfig()
	policy := &HumanPolicy{}

	engine, err := NewEngine(policy, nil, cfg, nil, nil)
	require.NoError(t, err)
	defer engine.Close()

	ctx := context.Background()
	ectx := &EngineContext{Context: ctx, Policy: policy}

	profile := DefaultProfile()
	priv, pub, err := profile.GenerateHybridKeyPair()
	require.NoError(t, err)

	t.Run("WrapUnwrap", func(t *testing.T) {
		// 1. Wrap
		res, err := engine.Wrap(ectx, pub)
		require.NoError(t, err)
		assert.Len(t, res.Plaintext, 32)
		assert.NotEmpty(t, res.Wrapped)

		// 2. Unwrap
		unwrapped, err := engine.Unwrap(ectx, res.Wrapped, priv)
		require.NoError(t, err)
		assert.Equal(t, res.Plaintext, unwrapped)
	})

	t.Run("WrapInvalidKey", func(t *testing.T) {
		_, err := engine.Wrap(ectx, []byte("too short"))
		assert.Error(t, err)
	})

	t.Run("UnwrapInvalidKey", func(t *testing.T) {
		res, _ := engine.Wrap(ectx, pub)
		_, err := engine.Unwrap(ectx, res.Wrapped, []byte("wrong priv key"))
		assert.Error(t, err)
	})
}
