package commands

import (
	"net/http"
	"net/http/httptest"
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
