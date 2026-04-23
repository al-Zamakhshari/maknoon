package crypto

import (
	"testing"
)

type MockRegistry struct {
	IdentityRegistry
}

func TestRegistryFactory(t *testing.T) {
	// Register a mock registry
	RegisterRegistry("mock-factory-test", func() IdentityRegistry {
		return &MockRegistry{}
	})

	// Backup and override config for test
	conf := GetGlobalConfig()
	old := conf.IdentityRegistries
	conf.IdentityRegistries = []string{"mock-factory-test"}
	defer func() { conf.IdentityRegistries = old }()

	reg := NewIdentityRegistry()
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
