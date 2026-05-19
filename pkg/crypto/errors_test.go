package crypto

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestTypedErrors(t *testing.T) {
	t.Run("PolicyViolation", func(t *testing.T) {
		err := &ErrPolicyViolation{Reason: "denied", Path: "/etc/passwd"}
		var target *ErrPolicyViolation
		if !As(err, &target) {
			t.Fatal("failed to assert ErrPolicyViolation")
		}
		if target.Path != "/etc/passwd" {
			t.Errorf("expected path /etc/passwd, got %s", target.Path)
		}
		if !target.IsSecurityViolation() {
			t.Error("expected IsSecurityViolation to be true")
		}
	})

	t.Run("Authentication", func(t *testing.T) {
		err := &ErrAuthentication{Reason: "wrong password"}
		var target *ErrAuthentication
		if !As(err, &target) {
			t.Fatal("failed to assert ErrAuthentication")
		}
		if target.IsSecurityViolation() {
			t.Error("expected IsSecurityViolation to be false")
		}
	})

	t.Run("Wrapping", func(t *testing.T) {
		inner := &ErrCrypto{Reason: "mac mismatch"}
		// Use fmt.Errorf with %w to allow error unwrapping
		outer := fmt.Errorf("wrapped: %w", inner)

		var target *ErrCrypto
		if !As(outer, &target) {
			t.Fatal("failed to assert wrapped ErrCrypto")
		}
	})

	t.Run("PolicyViolationVerbose", func(t *testing.T) {
		err := &ErrPolicyViolation{
			PolicyName: "restricted-agent",
			Capability: "identity",
		}
		expected := "security policy 'restricted-agent' violation: capability 'identity' is prohibited"
		if err.Error() != expected {
			t.Errorf("expected '%s', got '%s'", expected, err.Error())
		}
	})

	t.Run("PolicyViolationWithPath", func(t *testing.T) {
		err := &ErrPolicyViolation{
			PolicyName: "file-policy",
			Reason:     "access denied",
			Path:       "/etc/passwd",
		}
		expected := "security policy 'file-policy' violation: access denied at '/etc/passwd'"
		if err.Error() != expected {
			t.Errorf("expected '%s', got '%s'", expected, err.Error())
		}
	})
}

func TestErrStateError(t *testing.T) {
	e := &ErrState{Reason: "engine not initialized"}
	if !strings.Contains(e.Error(), "engine not initialized") {
		t.Errorf("unexpected: %s", e.Error())
	}
	if e.IsSecurityViolation() {
		t.Error("ErrState should not be a security violation")
	}
}

func TestErrFormatError(t *testing.T) {
	e := &ErrFormat{Reason: "bad magic header"}
	if !strings.Contains(e.Error(), "bad magic header") {
		t.Errorf("unexpected: %s", e.Error())
	}
	if e.IsSecurityViolation() {
		t.Error("ErrFormat should not be a security violation")
	}
}

func TestErrNetworkError(t *testing.T) {
	e := &ErrNetwork{Reason: "timeout", Source: "dns"}
	if !strings.Contains(e.Error(), "timeout") {
		t.Errorf("error missing reason: %s", e.Error())
	}
	if e.IsSecurityViolation() {
		t.Error("ErrNetwork should not be a security violation")
	}
}

func TestErrIOError(t *testing.T) {
	e := &ErrIO{Path: "/tmp/file.makn", Reason: "disk full"}
	if !strings.Contains(e.Error(), "disk full") {
		t.Errorf("error missing reason: %s", e.Error())
	}
	if e.IsSecurityViolation() {
		t.Error("ErrIO should not be a security violation")
	}
}

// --- FormatMCPError ---

func TestFormatMCPErrorTypes(t *testing.T) {
	tests := []struct {
		err      error
		wantType string
	}{
		{&ErrPolicyViolation{Reason: "blocked"}, "security_policy_violation"},
		{&ErrAuthentication{Reason: "bad pass"}, "authentication_failure"},
		{&ErrFormat{Reason: "bad magic"}, "format_error"},
		{&ErrCrypto{Reason: "mac fail"}, "crypto_failure"},
		{&ErrIO{Reason: "not found"}, "io_error"},
		{&ErrNetwork{Reason: "timeout"}, "network_error"},
	}
	for _, tt := range tests {
		res, err := FormatMCPError(tt.err, "test_tool")
		if err != nil {
			t.Fatalf("FormatMCPError(%T): %v", tt.err, err)
		}
		if res == nil {
			t.Fatalf("FormatMCPError(%T) returned nil result", tt.err)
		}
		// Result must be an error result.
		if !res.IsError {
			t.Errorf("%T: expected IsError=true", tt.err)
		}
		// Content must contain the type tag.
		found := false
		for _, c := range res.Content {
			if strings.Contains(fmt.Sprintf("%v", c), tt.wantType) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%T: expected type %q in content: %v", tt.err, tt.wantType, res.Content)
		}
	}
}

func TestFormatMCPErrorUnknownType(t *testing.T) {
	// A plain errors.New value hits the default branch.
	res, err := FormatMCPError(errors.New("something went wrong"), "my_tool")
	if err != nil {
		t.Fatalf("FormatMCPError: %v", err)
	}
	if res == nil || !res.IsError {
		t.Error("expected error result for unknown error type")
	}
}

func TestFormatMCPErrorToolName(t *testing.T) {
	res, _ := FormatMCPError(&ErrCrypto{Reason: "x"}, "encrypt_file")
	for _, c := range res.Content {
		if strings.Contains(fmt.Sprintf("%v", c), "encrypt_file") {
			return
		}
	}
	t.Error("tool name 'encrypt_file' not found in FormatMCPError content")
}

// --- isErrAuthentication ---

func TestIsErrAuthenticationTrue(t *testing.T) {
	ae := &ErrAuthentication{Reason: "bad key"}
	var target *ErrAuthentication
	if !isErrAuthentication(ae, &target) {
		t.Error("expected true for ErrAuthentication")
	}
	if target == nil || target.Reason != "bad key" {
		t.Errorf("target not set correctly: %v", target)
	}
}

func TestIsErrAuthenticationWrapped(t *testing.T) {
	inner := &ErrAuthentication{Reason: "wrapped"}
	wrapped := fmt.Errorf("outer: %w", inner)
	var target *ErrAuthentication
	if !isErrAuthentication(wrapped, &target) {
		t.Error("expected true for wrapped ErrAuthentication")
	}
}

func TestIsErrAuthenticationFalse(t *testing.T) {
	if isErrAuthentication(&ErrCrypto{Reason: "x"}, nil) {
		t.Error("expected false for non-ErrAuthentication")
	}
}

func TestIsErrAuthenticationNil(t *testing.T) {
	if isErrAuthentication(nil, nil) {
		t.Error("expected false for nil error")
	}
}

func TestMaknoonErrorInterfaceSatisfied(t *testing.T) {
	errs := []MaknoonError{
		&ErrPolicyViolation{Reason: "x"},
		&ErrAuthentication{Reason: "x"},
		&ErrCrypto{Reason: "x"},
		&ErrState{Reason: "x"},
		&ErrFormat{Reason: "x"},
		&ErrNetwork{Reason: "x"},
		&ErrIO{Reason: "x"},
	}
	for _, e := range errs {
		if e.Error() == "" {
			t.Errorf("%T.Error() is empty", e)
		}
	}
}
