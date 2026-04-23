package crypto

import (
	"fmt"
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
}
