package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
)

func TestCompletions(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	ResetGlobalContext()
	if err := InitEngine(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if GlobalContext.Engine != nil {
			GlobalContext.Engine.Close()
		}
	}()

	// 1. Identities
	keygenCmd := KeygenCmd()
	keygenCmd.SetArgs([]string{"-o", "test-id", "--no-password"})
	if err := keygenCmd.Execute(); err != nil {
		t.Fatal(err)
	}

	ids, _ := completeIdentities(nil, nil, "test")
	if len(ids) == 0 || ids[0] != "test-id" {
		t.Errorf("Identity completion failed, got: %v", ids)
	}

	// 2. Vaults
	vaultPath := filepath.Join(tmpDir, crypto.MaknoonDir, crypto.VaultsDir, "work.vault")
	if err := os.WriteFile(vaultPath, []byte("dummy"), 0600); err != nil {
		t.Fatal(err)
	}

	vaults, _ := completeVaults(nil, nil, "wo")
	if len(vaults) == 0 || vaults[0] != "work" {
		t.Errorf("Vault completion failed, got: %v", vaults)
	}

	// 3. Profiles
	profs, _ := completeProfiles(nil, nil, "ni")
	if len(profs) == 0 || profs[0] != "nist" {
		t.Errorf("Profile completion failed, got: %v", profs)
	}
}
