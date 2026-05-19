package crypto

// Tests for AuditEngine delegate methods not covered by audit_test.go.
// Pattern: call the method, verify MockAuditLogger captured the right action.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// --- Unprotect ---

func TestAuditUnprotectLogging(t *testing.T) {
	ae, mock := captureAuditEngine(t)

	// Protect data first so we have something to unprotect.
	var ct bytes.Buffer
	r := bytes.NewReader([]byte("unprotect audit test"))
	_, _ = ae.Protect(nil, "data.bin", r, &ct, Options{Passphrase: []byte("pass")})

	var out bytes.Buffer
	ae.Unprotect(nil, bytes.NewReader(ct.Bytes()), &out, "", Options{Passphrase: []byte("pass")})

	if mock.LastAction != "unprotect" {
		t.Errorf("expected action 'unprotect', got %q", mock.LastAction)
	}
}

// --- VaultSplit / VaultRecover ---

func TestAuditVaultSplitLogging(t *testing.T) {
	ae, mock := captureAuditEngine(t)
	ae.VaultSplit(nil, "myvault.vault", 2, 3, "pass")
	if mock.LastAction != "vault_split" {
		t.Errorf("expected 'vault_split', got %q", mock.LastAction)
	}
}

func TestAuditVaultRecoverLogging(t *testing.T) {
	ae, mock := captureAuditEngine(t)
	ae.VaultRecover(nil, []string{"word1 word2 word3"}, "recovered.vault", "", "pass")
	if mock.LastAction != "vault_recover" {
		t.Errorf("expected 'vault_recover', got %q", mock.LastAction)
	}
}

// --- Identity methods ---

func TestAuditIdentityActiveLogging(t *testing.T) {
	ae, _ := captureAuditEngine(t)
	// IdentityActive doesn't log (pure passthrough) — just verify it doesn't panic.
	_, _ = ae.IdentityActive(nil)
}

func TestAuditIdentityRenameLogging(t *testing.T) {
	ae, mock := captureAuditEngine(t)
	ae.IdentityRename(nil, "old", "new")
	if mock.LastAction != "identity_rename" {
		t.Errorf("expected 'identity_rename', got %q", mock.LastAction)
	}
}

func TestAuditIdentityPublishLogging(t *testing.T) {
	ae, mock := captureAuditEngine(t)
	ae.IdentityPublish(nil, "@alice@example.com", IdentityPublishOptions{WKD: true})
	if mock.LastAction != "identity_publish" {
		t.Errorf("expected 'identity_publish', got %q", mock.LastAction)
	}
}

func TestAuditIdentitySplitLogging(t *testing.T) {
	ae, mock := captureAuditEngine(t)
	ae.IdentitySplit(nil, "nonexistent-id", 2, 3, "")
	if mock.LastAction != "identity_split" {
		t.Errorf("expected 'identity_split', got %q", mock.LastAction)
	}
}

// --- Contact methods ---

func TestAuditContactAddLogging(t *testing.T) {
	ae, mock := captureAuditEngine(t)
	// Hex-encode dummy keys to satisfy hex.DecodeString.
	kemHex := "0001020304050607"
	sigHex := "0001020304050607"
	ae.ContactAdd(nil, "@bob", kemHex, sigHex, "test contact")
	if mock.LastAction != "contact_add" {
		t.Errorf("expected 'contact_add', got %q", mock.LastAction)
	}
	if mock.LastMetadata["petname"] != "@bob" {
		t.Errorf("expected petname '@bob', got %v", mock.LastMetadata["petname"])
	}
}

func TestAuditContactDeleteLogging(t *testing.T) {
	ae, mock := captureAuditEngine(t)
	ae.ContactDelete(nil, "@bob")
	if mock.LastAction != "contact_delete" {
		t.Errorf("expected 'contact_delete', got %q", mock.LastAction)
	}
	if mock.LastMetadata["petname"] != "@bob" {
		t.Errorf("expected petname '@bob', got %v", mock.LastMetadata["petname"])
	}
}

func TestAuditContactListPassthrough(t *testing.T) {
	ae, _ := captureAuditEngine(t)
	// ContactList is a passthrough with no logging — just ensure no panic.
	_, _ = ae.ContactList(nil)
}

// --- Secure delete / shred ---

func TestAuditSecureDeleteLogging(t *testing.T) {
	ae, mock := captureAuditEngine(t)
	tmp := filepath.Join(t.TempDir(), "shred_me.bin")
	os.WriteFile(tmp, []byte("delete this"), 0600)

	ae.SecureDelete(tmp)
	if mock.LastAction != "secure_delete" {
		t.Errorf("expected 'secure_delete', got %q", mock.LastAction)
	}
}

// --- Sign ---

func TestAuditSignLogging(t *testing.T) {
	ae, mock := captureAuditEngine(t)
	_, _, _, sigPriv, _ := GeneratePQKeyPair(1)
	ae.Sign(nil, []byte("sign this"), sigPriv)
	if mock.LastAction != "sign" {
		t.Errorf("expected 'sign', got %q", mock.LastAction)
	}
	if mock.LastMetadata["data_size"] == nil {
		t.Error("expected data_size in metadata")
	}
}

// --- Fragment / Reassemble ---

func TestAuditFragmentLogging(t *testing.T) {
	ae, mock := captureAuditEngine(t)
	tmp := t.TempDir()
	src := filepath.Join(tmp, "frag_test.bin")
	os.WriteFile(src, make([]byte, 256), 0600)

	ae.FragmentFile(nil, src, FragmentOptions{
		DataShards:   2,
		ParityShards: 1,
		TargetDir:    filepath.Join(tmp, "shards"),
	})
	if mock.LastAction != "fragment_file" {
		t.Errorf("expected 'fragment_file', got %q", mock.LastAction)
	}
}

func TestAuditReassembleLogging(t *testing.T) {
	ae, mock := captureAuditEngine(t)
	tmp := t.TempDir()

	// Fragment first so we have shards to reassemble.
	src := filepath.Join(tmp, "data.bin")
	os.WriteFile(src, make([]byte, 256), 0600)
	shardsDir := filepath.Join(tmp, "shards")
	ae.FragmentFile(nil, src, FragmentOptions{
		DataShards:   2,
		ParityShards: 1,
		TargetDir:    shardsDir,
	})

	out := filepath.Join(tmp, "out.bin")
	ae.ReassembleToPath(nil, shardsDir, out, nil)
	if mock.LastAction != "fragment_reassemble" {
		t.Errorf("expected 'fragment_reassemble', got %q", mock.LastAction)
	}
}

// --- Config / Profile ---

func TestAuditGetConfigPassthrough(t *testing.T) {
	ae, _ := captureAuditEngine(t)
	conf := ae.GetConfig()
	if conf == nil {
		t.Error("GetConfig returned nil")
	}
}

func TestAuditGetPolicyPassthrough(t *testing.T) {
	ae, _ := captureAuditEngine(t)
	pol := ae.GetPolicy()
	if pol == nil {
		t.Error("GetPolicy returned nil")
	}
}

func TestAuditSanitizePath(t *testing.T) {
	ae, _ := captureAuditEngine(t)
	// "-" and "" should pass through unchanged.
	if ae.sanitizePath("-") != "-" {
		t.Error("sanitizePath('-') should return '-'")
	}
	if ae.sanitizePath("") != "" {
		t.Error("sanitizePath('') should return ''")
	}
	// An absolute path not under HOME should return the basename.
	got := ae.sanitizePath("/tmp/some/deep/file.txt")
	if got != "file.txt" {
		t.Errorf("sanitizePath outside HOME = %q, want %q", got, "file.txt")
	}
}
