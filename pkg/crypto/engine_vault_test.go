package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- VaultSession tests ---

func TestVaultSessionUnlockGet(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("session-pass")
	entry := &VaultEntry{Service: "svc", Password: []byte("secret")}

	// Populate the vault.
	if err := e.VaultSet(nil, "sess.vault", entry, pass, "", false); err != nil {
		t.Fatalf("VaultSet: %v", err)
	}

	// Unlock — derives key once.
	if err := e.VaultUnlock(nil, "sess.vault", pass, 60); err != nil {
		t.Fatalf("VaultUnlock: %v", err)
	}

	// Get with nil passphrase — must use session key.
	got, err := e.VaultGet(nil, "sess.vault", "svc", nil, "")
	if err != nil {
		t.Fatalf("VaultGet with session: %v", err)
	}
	if string(got.Password) != "secret" {
		t.Errorf("password = %q, want %q", got.Password, "secret")
	}
}

func TestVaultSessionUnlockList(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("list-session-pass")
	for _, svc := range []string{"a", "b", "c"} {
		e.VaultSet(nil, "listses.vault", &VaultEntry{Service: svc, Password: []byte("x")}, pass, "", false)
	}

	if err := e.VaultUnlock(nil, "listses.vault", pass, 60); err != nil {
		t.Fatalf("VaultUnlock: %v", err)
	}

	entries, err := e.VaultList(nil, "listses.vault", nil)
	if err != nil {
		t.Fatalf("VaultList with session: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

func TestVaultSessionLock(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("lock-pass")
	e.VaultSet(nil, "lock2.vault", &VaultEntry{Service: "s", Password: []byte("x")}, pass, "", false)
	e.VaultUnlock(nil, "lock2.vault", pass, 60)

	// Lock immediately.
	if err := e.VaultLock(nil, "lock2.vault"); err != nil {
		t.Fatalf("VaultLock: %v", err)
	}

	// Get with nil passphrase must fail — session is gone, no KDF possible.
	_, err := e.VaultGet(nil, "lock2.vault", "s", nil, "")
	if err == nil {
		t.Error("expected error after VaultLock with nil passphrase")
	}
}

func TestVaultSessionExpiry(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("expiry-sess-pass")
	e.VaultSet(nil, "expiry2.vault", &VaultEntry{Service: "s", Password: []byte("x")}, pass, "", false)

	// Unlock with a 1-second TTL.
	if err := e.VaultUnlock(nil, "expiry2.vault", pass, 1); err != nil {
		t.Fatalf("VaultUnlock: %v", err)
	}

	// Should work immediately.
	if _, err := e.VaultGet(nil, "expiry2.vault", "s", nil, ""); err != nil {
		t.Fatalf("VaultGet within TTL: %v", err)
	}

	// Wait for TTL to expire.
	time.Sleep(1200 * time.Millisecond)

	// Session expired — nil passphrase must fail.
	_, err := e.VaultGet(nil, "expiry2.vault", "s", nil, "")
	if err == nil {
		t.Error("expected error after session TTL expiry with nil passphrase")
	}
}

func TestVaultSessionWrongKeyCleared(t *testing.T) {
	e := engineForVault(t)
	correctPass := []byte("correct")
	wrongPass := []byte("wrong")

	e.VaultSet(nil, "wk.vault", &VaultEntry{Service: "s", Password: []byte("v")}, correctPass, "", false)

	// Unlock with wrong passphrase — key is cached but wrong.
	e.VaultUnlock(nil, "wk.vault", wrongPass, 60)

	// Get should fail and clear the bad session.
	_, err := e.VaultGet(nil, "wk.vault", "s", wrongPass, "")
	if err == nil {
		t.Error("expected error when using wrong session key")
	}

	// After the bad session is cleared, correct passphrase should work normally.
	got, err := e.VaultGet(nil, "wk.vault", "s", correctPass, "")
	if err != nil {
		t.Fatalf("VaultGet with correct passphrase after bad session: %v", err)
	}
	if string(got.Password) != "v" {
		t.Errorf("password = %q, want %q", got.Password, "v")
	}
}

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

// --- checkLockout: active lockout window ---

func TestVaultGetLockedOut(t *testing.T) {
	e := engineForVault(t)
	e.Config.VaultMaxFailAttempts = 2
	e.Config.VaultLockoutMinutes = 60

	pass := []byte("correct-pass")
	wrong := []byte("wrong-pass")
	if err := e.VaultSet(nil, "lock.vault", &VaultEntry{Service: "svc", Password: []byte("secret")}, pass, "", false); err != nil {
		t.Fatalf("VaultSet: %v", err)
	}

	// Two failed Get attempts to fill the sidecar counter.
	e.VaultGet(nil, "lock.vault", "svc", wrong, "")
	e.VaultGet(nil, "lock.vault", "svc", wrong, "")

	// Third attempt — even with the correct passphrase — should hit the lockout.
	_, err := e.VaultGet(nil, "lock.vault", "svc", pass, "")
	if err == nil {
		t.Fatal("expected lockout error after max failed attempts")
	}
	if !strings.Contains(err.Error(), "locked") {
		t.Errorf("expected lockout message, got: %v", err)
	}
}

// --- checkLockout: expired window clears and allows access ---

func TestVaultGetLockoutExpired(t *testing.T) {
	e := engineForVault(t)
	e.Config.VaultMaxFailAttempts = 1
	e.Config.VaultLockoutMinutes = 1

	pass := []byte("expiry-pass")
	wrong := []byte("bad")
	if err := e.VaultSet(nil, "exp.vault", &VaultEntry{Service: "svc", Password: []byte("val")}, pass, "", false); err != nil {
		t.Fatalf("VaultSet: %v", err)
	}

	// Trigger one failed attempt.
	e.VaultGet(nil, "exp.vault", "svc", wrong, "")

	// Manually backdate the sidecar's Since timestamp so the lockout window appears expired.
	vs := e.Vault
	resolvedPath, _ := vs.resolveVaultPath("exp.vault")
	vs.writeAttempts(resolvedPath, vaultAttempts{Count: 1, Since: time.Now().Add(-2 * time.Minute)})

	// Now a correct Get should succeed because the lockout window has passed.
	entry, err := e.VaultGet(nil, "exp.vault", "svc", pass, "")
	if err != nil {
		t.Fatalf("expected success after lockout expiry, got: %v", err)
	}
	if string(entry.Password) != "val" {
		t.Errorf("password = %q, want %q", entry.Password, "val")
	}
}

// --- VaultRename: error paths ---

func TestVaultRenameNonExistent(t *testing.T) {
	e := engineForVault(t)
	err := e.VaultRename(nil, "ghost.vault", "new.vault")
	if err == nil {
		t.Error("expected error renaming nonexistent vault")
	}
}

func TestVaultRenameTargetExists(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("p")
	e.VaultSet(nil, "src.vault", &VaultEntry{Service: "s", Password: []byte("x")}, pass, "", false)
	e.VaultSet(nil, "dst.vault", &VaultEntry{Service: "s", Password: []byte("x")}, pass, "", false)

	err := e.VaultRename(nil, "src.vault", "dst.vault")
	if err == nil {
		t.Error("expected error renaming to an already-existing vault")
	}
}

// --- VaultInitInstitutional: vault already exists ---

func TestVaultInitInstitutionalAlreadyExists(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("inst-pass")
	// Create the vault first via a regular Set.
	e.VaultSet(nil, "inst.vault", &VaultEntry{Service: "s", Password: []byte("x")}, pass, "", false)

	_, err := e.VaultInitInstitutional(nil, "inst.vault", 2, 3, []string{"p1", "p2", "p3"}, pass)
	if err == nil {
		t.Error("expected error initializing institutional vault that already exists")
	}
}

// --- ProtectDirectory ---

func TestProtectDirectorySessionKeyDerived(t *testing.T) {
	e := engineForVault(t)
	src := t.TempDir()
	dst := t.TempDir()

	// Create three files.
	for i, content := range []string{"alpha", "beta", "gamma"} {
		os.WriteFile(filepath.Join(src, fmt.Sprintf("file%d.txt", i)), []byte(content), 0600)
	}

	pass := []byte("dir-pass")
	opts := Options{Passphrase: pass}
	res, err := e.ProtectDirectory(nil, src, dst, opts)
	if err != nil {
		t.Fatalf("ProtectDirectory: %v", err)
	}
	if res.TotalFiles != 3 {
		t.Errorf("expected 3 files encrypted, got %d", res.TotalFiles)
	}
	if !res.SessionKeyDerived {
		t.Error("expected session_key_derived=true for passphrase-based recursive encrypt")
	}
	if res.Status != "success" {
		t.Errorf("status = %q, want success", res.Status)
	}
	// Verify .makn files exist in dst.
	for i := range []string{"alpha", "beta", "gamma"} {
		p := filepath.Join(dst, fmt.Sprintf("file%d.txt.makn", i))
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s to exist: %v", p, err)
		}
	}
}

func TestProtectDirectorySkipsAlreadyEncrypted(t *testing.T) {
	e := engineForVault(t)
	src := t.TempDir()

	os.WriteFile(filepath.Join(src, "a.txt"), []byte("data"), 0600)
	os.WriteFile(filepath.Join(src, "b.makn"), []byte("already encrypted"), 0600)

	res, err := e.ProtectDirectory(nil, src, "", Options{Passphrase: []byte("p")})
	if err != nil {
		t.Fatalf("ProtectDirectory: %v", err)
	}
	if res.TotalFiles != 1 {
		t.Errorf("expected 1 file encrypted, got %d", res.TotalFiles)
	}
	if len(res.Skipped) != 1 {
		t.Errorf("expected 1 skipped file, got %d", len(res.Skipped))
	}
}

// --- ResolveIdentityInfo ---

func TestResolveIdentityInfoLocalFile(t *testing.T) {
	e := engineForVault(t)
	tmp := t.TempDir()
	// Create a keygen identity.
	ectx := &EngineContext{Context: nil, Policy: &HumanPolicy{}}
	res, err := e.CreateIdentity(ectx, filepath.Join(tmp, "alice"), nil, "", false, "nist")
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}

	// Resolve the KEM public key file path.
	record, err := e.ResolveIdentityInfo(nil, res.BasePath+".kem.pub", false)
	if err != nil {
		t.Fatalf("ResolveIdentityInfo local: %v", err)
	}
	if len(record.KEMPubKey) == 0 {
		t.Error("expected non-empty KEMPubKey for local file resolution")
	}
	// Local file resolution does not populate SIGPubKey — that's expected.
	if len(record.SIGPubKey) != 0 {
		t.Error("local file resolution should not populate SIGPubKey")
	}
}

// --- DecryptDirectory ---

func TestDecryptDirectory(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("dir-decrypt-pass")

	src := t.TempDir()
	enc := t.TempDir()
	dec := t.TempDir()

	// Write three plaintext files and encrypt them.
	for i, content := range []string{"aaa", "bbb", "ccc"} {
		p := filepath.Join(src, fmt.Sprintf("f%d.txt", i))
		os.WriteFile(p, []byte(content), 0600)
	}

	encRes, err := e.ProtectDirectory(nil, src, enc, Options{Passphrase: pass})
	if err != nil {
		t.Fatalf("ProtectDirectory: %v", err)
	}
	if encRes.TotalFiles != 3 {
		t.Fatalf("expected 3 encrypted files, got %d", encRes.TotalFiles)
	}

	// Decrypt the directory.
	decRes, err := e.DecryptDirectory(nil, enc, dec, Options{Passphrase: pass})
	if err != nil {
		t.Fatalf("DecryptDirectory: %v", err)
	}
	if decRes.TotalFiles != 3 {
		t.Errorf("expected 3 decrypted files, got %d", decRes.TotalFiles)
	}
	if decRes.Status != "success" {
		t.Errorf("status = %q, want success", decRes.Status)
	}

	// Verify content of one recovered file.
	for i, want := range []string{"aaa", "bbb", "ccc"} {
		got, err := os.ReadFile(filepath.Join(dec, fmt.Sprintf("f%d.txt", i)))
		if err != nil {
			t.Errorf("f%d.txt not found: %v", i, err)
			continue
		}
		if strings.TrimSpace(string(got)) != want {
			t.Errorf("f%d.txt = %q, want %q", i, got, want)
		}
	}
}

func TestDecryptDirectoryPartialFailure(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("partial-pass")
	dir := t.TempDir()

	// Put a non-.makn file — should be skipped, not an error.
	os.WriteFile(filepath.Join(dir, "not-encrypted.txt"), []byte("plain"), 0600)
	// Put a corrupt .makn file — should produce an error entry.
	os.WriteFile(filepath.Join(dir, "corrupt.makn"), []byte("not a real makn file"), 0600)

	res, err := e.DecryptDirectory(nil, dir, "", Options{Passphrase: pass})
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}
	if res.Status != "partial" {
		t.Errorf("status = %q, want partial", res.Status)
	}
	if len(res.Errors) == 0 {
		t.Error("expected at least one error for corrupt.makn")
	}
	if len(res.Skipped) == 0 {
		t.Error("expected not-encrypted.txt to be skipped")
	}
}

// --- ProtectFiles / DecryptFiles ---

func TestProtectFilesAndDecryptFiles(t *testing.T) {
	e := engineForVault(t)
	pass := []byte("files-pass")
	tmp := t.TempDir()

	// Create source files.
	files := []string{}
	for i, content := range []string{"x", "y", "z"} {
		p := filepath.Join(tmp, fmt.Sprintf("src%d.txt", i))
		os.WriteFile(p, []byte(content), 0600)
		files = append(files, p)
	}

	outDir := t.TempDir()
	res, err := e.ProtectFiles(nil, files, outDir, Options{Passphrase: pass})
	if err != nil {
		t.Fatalf("ProtectFiles: %v", err)
	}
	if res.TotalFiles != 3 {
		t.Errorf("expected 3 files, got %d", res.TotalFiles)
	}
	if !res.SessionKeyDerived {
		t.Error("expected session key auto-derived for passphrase path")
	}

	// Collect .makn paths.
	makns := []string{}
	for _, r := range res.Encrypted {
		makns = append(makns, r.Output)
	}

	decDir := t.TempDir()
	decRes, err := e.DecryptFiles(nil, makns, decDir, Options{Passphrase: pass})
	if err != nil {
		t.Fatalf("DecryptFiles: %v", err)
	}
	if decRes.TotalFiles != 3 {
		t.Errorf("expected 3 decrypted files, got %d", decRes.TotalFiles)
	}
}
