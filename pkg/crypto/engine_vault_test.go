package crypto

import (
	"os"
	"strings"
	"testing"
)

// engineForVault returns a fully initialised engine wired to a temp HOME.
func engineForVault(t *testing.T) *Engine {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	conf := DefaultConfig()
	e, err := NewEngine(&HumanPolicy{}, nil, conf, nil, nil)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// --- VaultSet / VaultGet ---

func TestVaultSetAndGet(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("vault-test-pass")
	entry := &VaultEntry{Service: "github", Username: "alice", Password: []byte("token123")}

	if err := e.VaultSet(nil, "test.vault", entry, pass, "", false); err != nil {
		t.Fatalf("VaultSet: %v", err)
	}

	got, err := e.VaultGet(nil, "test.vault", "github", pass, "")
	if err != nil {
		t.Fatalf("VaultGet: %v", err)
	}
	if got.Username != "alice" {
		t.Errorf("Username = %q, want %q", got.Username, "alice")
	}
	if string(got.Password) != "token123" {
		t.Errorf("Password = %q, want %q", got.Password, "token123")
	}
}

func TestVaultSetOverwriteFalseRejects(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("pass")
	entry := &VaultEntry{Service: "svc", Password: []byte("v1")}

	e.VaultSet(nil, "dupe.vault", entry, pass, "", false)
	err := e.VaultSet(nil, "dupe.vault", entry, pass, "", false)
	if err == nil {
		t.Error("expected error on duplicate set with overwrite=false")
	}
}

func TestVaultSetOverwriteTrue(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("pass")

	e.VaultSet(nil, "ow.vault", &VaultEntry{Service: "s", Password: []byte("v1")}, pass, "", false)
	if err := e.VaultSet(nil, "ow.vault", &VaultEntry{Service: "s", Password: []byte("v2")}, pass, "", true); err != nil {
		t.Fatalf("overwrite=true should succeed: %v", err)
	}
	got, _ := e.VaultGet(nil, "ow.vault", "s", pass, "")
	if string(got.Password) != "v2" {
		t.Errorf("expected v2 after overwrite, got %q", got.Password)
	}
}

func TestVaultGetMissingKey(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("pass")
	e.VaultSet(nil, "miss.vault", &VaultEntry{Service: "exists", Password: []byte("x")}, pass, "", false)

	_, err := e.VaultGet(nil, "miss.vault", "does-not-exist", pass, "")
	if err == nil {
		t.Error("expected error for missing service key")
	}
}

// --- VaultList ---

func TestVaultList(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("pass")

	for _, svc := range []string{"github", "gitlab", "bitbucket"} {
		e.VaultSet(nil, "list.vault", &VaultEntry{Service: svc, Password: []byte("s")}, pass, "", false)
	}

	entries, err := e.VaultList(nil, "list.vault", pass)
	if err != nil {
		t.Fatalf("VaultList: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

// --- VaultDelete ---

func TestVaultDelete(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("pass")
	e.VaultSet(nil, "del.vault", &VaultEntry{Service: "s", Password: []byte("x")}, pass, "", false)

	if err := e.VaultDelete(nil, "del.vault"); err != nil {
		t.Fatalf("VaultDelete: %v", err)
	}
	// After delete, listing should fail or return empty.
	_, err := e.VaultList(nil, "del.vault", pass)
	if err == nil {
		t.Error("expected error after vault deletion")
	}
}

// --- VaultRename ---

func TestVaultRename(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("pass")
	e.VaultSet(nil, "old.vault", &VaultEntry{Service: "s", Password: []byte("x")}, pass, "", false)

	if err := e.VaultRename(nil, "old.vault", "new.vault"); err != nil {
		t.Fatalf("VaultRename: %v", err)
	}
	entries, err := e.VaultList(nil, "new.vault", pass)
	if err != nil || len(entries) == 0 {
		t.Errorf("renamed vault should be accessible: err=%v entries=%d", err, len(entries))
	}
}

// --- VaultStatus ---

func TestVaultStatus(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("pass")
	e.VaultSet(nil, "status.vault", &VaultEntry{Service: "s", Password: []byte("x")}, pass, "", false)

	res, err := e.VaultStatus(nil, "status.vault")
	if err != nil {
		t.Fatalf("VaultStatus: %v", err)
	}
	if res == nil {
		t.Error("VaultStatus returned nil result")
	}
}

// --- VaultRotate ---

func TestVaultRotate(t *testing.T) {
	e := engineForVault(t)
	oldPass := []byte("old-pass")
	newPass := []byte("new-pass")

	e.VaultSet(nil, "rot.vault", &VaultEntry{Service: "s", Password: []byte("sec")}, oldPass, "", false)

	if err := e.VaultRotate(nil, "rot.vault", oldPass, newPass); err != nil {
		t.Fatalf("VaultRotate: %v", err)
	}

	// Old pass must fail.
	_, err := e.VaultGet(nil, "rot.vault", "s", oldPass, "")
	if err == nil {
		t.Error("old passphrase should no longer work after rotation")
	}

	// New pass must succeed.
	got, err := e.VaultGet(nil, "rot.vault", "s", newPass, "")
	if err != nil {
		t.Fatalf("new passphrase failed: %v", err)
	}
	if string(got.Password) != "sec" {
		t.Errorf("secret = %q after rotation, want %q", got.Password, "sec")
	}
}

// --- VaultSplit / VaultRecover / VaultCheckShards ---

func TestVaultSplitAndRecover(t *testing.T) {
	e := engineForVault(t)
	pass := "split-pass"

	// Populate vault.
	e.VaultSet(nil, "split.vault", &VaultEntry{Service: "s", Password: []byte("secret-value")}, []byte(pass), "", false)

	shards, err := e.VaultSplit(nil, "split.vault", 2, 3, pass)
	if err != nil {
		t.Fatalf("VaultSplit: %v", err)
	}
	if len(shards) != 3 {
		t.Fatalf("expected 3 shards, got %d", len(shards))
	}

	// Recover using any 2 shards (threshold=2).
	recoveredPath, err := e.VaultRecover(nil, shards[:2], "split.vault", "recovered.vault", pass)
	if err != nil {
		t.Fatalf("VaultRecover: %v", err)
	}
	if recoveredPath == "" {
		t.Error("VaultRecover returned empty path")
	}
}

func TestVaultCheckShards(t *testing.T) {
	e := engineForVault(t)
	pass := "check-pass"
	e.VaultSet(nil, "check.vault", &VaultEntry{Service: "s", Password: []byte("x")}, []byte(pass), "", false)

	shards, err := e.VaultSplit(nil, "check.vault", 2, 3, pass)
	if err != nil {
		t.Fatalf("VaultSplit: %v", err)
	}

	res, err := e.VaultCheckShards(nil, shards)
	if err != nil {
		t.Fatalf("VaultCheckShards: %v", err)
	}
	if res == nil {
		t.Error("VaultCheckShards returned nil")
	}
}

// --- GeneratePassword / GeneratePassphrase via engine ---

func TestEngineGeneratePassword(t *testing.T) {
	e := engineForVault(t)
	p, err := e.GeneratePassword(nil, 20, false)
	if err != nil {
		t.Fatalf("GeneratePassword: %v", err)
	}
	if len(p) != 20 {
		t.Errorf("expected 20 chars, got %d", len(p))
	}
}

func TestEngineGeneratePassphrase(t *testing.T) {
	e := engineForVault(t)
	p, err := e.GeneratePassphrase(nil, 4, "-")
	if err != nil {
		t.Fatalf("GeneratePassphrase: %v", err)
	}
	if len(strings.Split(p, "-")) != 4 {
		t.Errorf("expected 4 words, got: %q", p)
	}
}

// --- SecureDelete via engine ---

func TestEngineSecureDelete(t *testing.T) {
	e := engineForVault(t)
	tmp := t.TempDir()
	f := tmp + "/shred_me.bin"
	os.WriteFile(f, []byte("sensitive"), 0600)

	if err := e.SecureDelete(f); err != nil {
		t.Fatalf("SecureDelete: %v", err)
	}
	if _, err := os.Stat(f); err == nil {
		t.Error("file should not exist after SecureDelete")
	}
}
