package crypto

import (
	"testing"
)

type MockRegistry struct {
	IdentityRegistry
}

func TestRegistryFactory(t *testing.T) {
	// Register a mock registry
	RegisterRegistry("mock-factory-test", func(conf *Config) IdentityRegistry {
		return &MockRegistry{}
	})

	// Create isolated config
	conf := &Config{
		IdentityRegistries: []string{"mock-factory-test"},
	}

	reg := NewIdentityRegistry(conf)
	mr, ok := reg.(*MultiRegistry)
	if !ok {
		t.Fatal("expected MultiRegistry")
	}

	found := false
	for _, r := range mr.Registries {
		if _, ok := r.(*MockRegistry); ok {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("MockRegistry not found in active registries. Active: %v", mr.Registries)
	}
}
