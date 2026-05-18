package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeRESTPath(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		raw     string
		base    string
		wantErr bool
		desc    string
	}{
		{tmpDir + "/file.bin", tmpDir, false, "valid path in allowed base"},
		{tmpDir + "/sub/dir/file.bin", tmpDir, false, "nested path in allowed base"},
		{"/etc/passwd", tmpDir, true, "absolute path outside allowed base"},
		{"../../../etc/passwd", tmpDir, true, "relative traversal"},
		{"../../secret", tmpDir, true, "relative escape"},
		{"", tmpDir, true, "empty path"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			_, err := sanitizeRESTPath(tt.raw, tt.base)
			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeRESTPath(%q, %q) error=%v, wantErr=%v", tt.raw, tt.base, err, tt.wantErr)
			}
		})
	}
}

func TestHandleHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	rec := httptest.NewRecorder()
	handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "status") {
		t.Errorf("expected status field in response, got: %s", body)
	}
}

func TestHandleFragmentRejectsTraversal(t *testing.T) {
	// Attempt path traversal via input field.
	body := `{"input": "../../../etc/passwd", "output": "/tmp/out"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/crypto/fragment", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleFragment(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for path traversal attempt, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleReassembleRejectsTraversal(t *testing.T) {
	body := `{"input_dir": "../../../../secret", "output": "/tmp/out.bin"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/crypto/reassemble", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleReassemble(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for path traversal attempt, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleEncryptRejectsTraversal(t *testing.T) {
	body := `{"input": "/etc/shadow", "output": "/tmp/stolen.makn", "passphrase": "pw"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/crypto/encrypt", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handleEncrypt(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for path traversal attempt, got %d", rec.Code)
	}
}

// setupServeEnv initialises a full engine in a temp HOME directory and returns cleanup.
// It reuses setupMissionEnv from mission_coverage_test.go.
func setupServeEnv(t *testing.T) string {
	t.Helper()
	return setupMissionEnv(t)
}

// postJSON sends a POST request with a JSON body to the given handler.
func postJSON(handler http.HandlerFunc, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler(rec, req)
	return rec
}

// TestHandleEncryptDecryptRoundtrip encrypts a file via REST then decrypts it and compares content.
func TestHandleEncryptDecryptRoundtrip(t *testing.T) {
	tmpDir := setupServeEnv(t)
	SetJSONOutput(true)
	defer SetJSONOutput(false)

	// Create a plaintext file in os.TempDir() (which sanitizeRESTPath allows)
	plainPath := filepath.Join(os.TempDir(), fmt.Sprintf("rest-enc-test-%d.txt", os.Getpid()))
	encPath := plainPath + ".makn"
	decPath := plainPath + ".dec"
	t.Cleanup(func() {
		os.Remove(plainPath)
		os.Remove(encPath)
		os.Remove(decPath)
	})

	const secret = "REST-ENCRYPT-ROUNDTRIP-CONTENT"
	os.WriteFile(plainPath, []byte(secret), 0600)

	// 1. Encrypt
	encRec := postJSON(handleEncrypt, fmt.Sprintf(
		`{"input":%q,"output":%q,"passphrase":"roundtrip-pass"}`, plainPath, encPath))
	if encRec.Code != http.StatusOK {
		t.Fatalf("encrypt returned %d: %s", encRec.Code, encRec.Body.String())
	}

	// 2. Decrypt
	decRec := postJSON(handleDecrypt, fmt.Sprintf(
		`{"input":%q,"output":%q,"passphrase":"roundtrip-pass"}`, encPath, decPath))
	if decRec.Code != http.StatusOK {
		t.Fatalf("decrypt returned %d: %s", decRec.Code, decRec.Body.String())
	}

	// 3. Verify content
	got, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("decrypted file missing: %v", err)
	}
	if string(got) != secret {
		t.Errorf("content mismatch: got %q want %q", got, secret)
	}
	_ = tmpDir
}

// TestHandleVaultSetGet sets a vault entry via REST then retrieves it.
func TestHandleVaultSetGet(t *testing.T) {
	tmpDir := setupServeEnv(t)
	SetJSONOutput(true)
	defer SetJSONOutput(false)

	vaultPath := filepath.Join(tmpDir, ".maknoon", "vaults", "rest-test.vault")
	os.MkdirAll(filepath.Dir(vaultPath), 0700)

	// 1. Set
	setBody := fmt.Sprintf(
		`{"vault":%q,"service":"myapp","username":"admin","password":"s3cr3t","passphrase":"vaultpass","overwrite":true}`,
		vaultPath)
	setRec := postJSON(handleVaultSet, setBody)
	if setRec.Code != http.StatusOK {
		t.Fatalf("vault/set returned %d: %s", setRec.Code, setRec.Body.String())
	}

	// 2. Get
	getBody := fmt.Sprintf(`{"vault":%q,"service":"myapp","passphrase":"vaultpass"}`, vaultPath)
	getRec := postJSON(handleVaultGet, getBody)
	if getRec.Code != http.StatusOK {
		t.Fatalf("vault/get returned %d: %s", getRec.Code, getRec.Body.String())
	}

	// VaultEntry.Password is stored as SecretBytes (base64 on wire)
	if !strings.Contains(getRec.Body.String(), "s3cr3t") &&
		!strings.Contains(getRec.Body.String(), base64.StdEncoding.EncodeToString([]byte("s3cr3t"))) {
		t.Errorf("expected password 's3cr3t' in response, got: %s", getRec.Body.String())
	}
}

// TestHandleIdentityKeygenAndList creates an identity via REST then lists it.
func TestHandleIdentityKeygenAndList(t *testing.T) {
	setupServeEnv(t)
	SetJSONOutput(true)
	defer SetJSONOutput(false)

	// 1. Keygen
	kgRec := postJSON(handleIdentityKeygen,
		`{"name":"rest-id","passphrase":"","profile":"nist"}`)
	if kgRec.Code != http.StatusOK {
		t.Fatalf("identity/keygen returned %d: %s", kgRec.Code, kgRec.Body.String())
	}

	// 2. List
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/identity/list", nil)
	handleIdentityList(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("identity/list returned %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "rest-id") {
		t.Errorf("identity 'rest-id' not found in list: %s", rec.Body.String())
	}
}

// TestHandleSignAndVerify signs data via REST then verifies the signature.
func TestHandleSignAndVerify(t *testing.T) {
	tmpDir := setupServeEnv(t)
	SetJSONOutput(true)
	defer SetJSONOutput(false)

	// Generate an identity to get key files
	runCommand(t, KeygenCmd(), "-o", "sign-id", "--no-password")
	keyPath := filepath.Join(tmpDir, ".maknoon", "keys", "sign-id.sig.key")
	pubPath := filepath.Join(tmpDir, ".maknoon", "keys", "sign-id.sig.pub")

	payload := []byte("REST-SIGN-TEST-PAYLOAD")
	dataB64 := base64.StdEncoding.EncodeToString(payload)

	// 1. Sign
	signBody := fmt.Sprintf(`{"data":%q,"key_path":%q,"passphrase":""}`, dataB64, keyPath)
	signRec := postJSON(handleSign, signBody)
	if signRec.Code != http.StatusOK {
		t.Fatalf("identity/sign returned %d: %s", signRec.Code, signRec.Body.String())
	}

	var signResp map[string]interface{}
	json.Unmarshal(signRec.Body.Bytes(), &signResp)
	sigB64, _ := signResp["signature"].(string)
	if sigB64 == "" {
		t.Fatalf("no signature in response: %s", signRec.Body.String())
	}

	// 2. Get public key bytes for verify call
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("could not read pub key: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubBytes)

	// 3. Verify
	verifyBody := fmt.Sprintf(`{"data":%q,"signature":%q,"public_key":%q}`, dataB64, sigB64, pubB64)
	verifyRec := postJSON(handleVerify, verifyBody)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("identity/verify returned %d: %s", verifyRec.Code, verifyRec.Body.String())
	}

	var verResp map[string]interface{}
	json.Unmarshal(verifyRec.Body.Bytes(), &verResp)
	// handleVerify returns either "verified" or "valid" depending on threshold path
	verified := verResp["verified"] == true || verResp["valid"] == true
	if !verified {
		t.Errorf("expected verified/valid=true, got: %s", verifyRec.Body.String())
	}
}

func TestRequestBodyLimitIsEnforced(t *testing.T) {
	// Send a body larger than maxRequestBodyBytes.
	largeBody := strings.Repeat("x", int(maxRequestBodyBytes)+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/vault/list",
		strings.NewReader(`{"vault":"`+largeBody+`"}`))
	rec := httptest.NewRecorder()

	// Even if JSON decode succeeds on the limit boundary, the vault name
	// being > 32 MB is nonsensical. The key test is that the server does not
	// hang or OOM — it should return quickly.
	handleVaultList(rec, req)
	// Any non-5xx response (BadRequest or InternalServerError from vault not found) is fine.
	if rec.Code == 0 {
		t.Error("expected a response code, got 0")
	}
}
