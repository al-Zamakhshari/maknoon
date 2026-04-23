package crypto

import (
	"errors"
	"fmt"
)

// As is a wrapper for errors.As.
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}

// Is is a wrapper for errors.Is.
func Is(err error, target error) bool {
	return errors.Is(err, target)
}

// MaknoonError is the base interface for all cryptographic and policy errors.
type MaknoonError interface {
	error
	IsSecurityViolation() bool
}

// ErrPolicyViolation occurs when a restricted sandbox policy is breached.
type ErrPolicyViolation struct {
	Reason string
	Path   string
}

func (e *ErrPolicyViolation) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("security policy violation: %s at '%s'", e.Reason, e.Path)
	}
	return fmt.Sprintf("security policy violation: %s", e.Reason)
}

func (e *ErrPolicyViolation) IsSecurityViolation() bool { return true }

// ErrAuthentication occurs when credentials (passphrase, PIN, signature) are invalid.
type ErrAuthentication struct {
	Reason string
}

func (e *ErrAuthentication) Error() string {
	return fmt.Sprintf("authentication failed: %s", e.Reason)
}

func (e *ErrAuthentication) IsSecurityViolation() bool { return false }

// ErrCrypto occurs during low-level cryptographic failures (MAC mismatch, bad header).
type ErrCrypto struct {
	Reason string
}

func (e *ErrCrypto) Error() string {
	return fmt.Sprintf("cryptographic failure: %s", e.Reason)
}

func (e *ErrCrypto) IsSecurityViolation() bool { return false }

// ErrState occurs when the system is not in a ready state (missing keys, db lock).
type ErrState struct {
	Reason string
}

func (e *ErrState) Error() string {
	return fmt.Sprintf("system state error: %s", e.Reason)
}

func (e *ErrState) IsSecurityViolation() bool { return false }
