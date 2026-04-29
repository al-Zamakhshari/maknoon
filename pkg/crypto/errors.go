package crypto

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
)

// FormatMCPError converts a Go error into a structured MCP ToolResultError.
func FormatMCPError(err error, tool string) (*mcp.CallToolResult, error) {
	resp := map[string]interface{}{"error": err.Error(), "tool": tool}
	var policyErr *ErrPolicyViolation
	if As(err, &policyErr) {
		resp["type"] = "security_policy_violation"
		resp["is_security_violation"] = true
	}
	raw, _ := json.Marshal(resp)
	return mcp.NewToolResultError(string(raw)), nil
}

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

// ErrFormat occurs when data does not match the expected wire format.
type ErrFormat struct {
	Reason string
}

func (e *ErrFormat) Error() string             { return fmt.Sprintf("format error: %s", e.Reason) }
func (e *ErrFormat) IsSecurityViolation() bool { return false }

// ErrNetwork occurs when a network-based operation (P2P, Registry) fails.
type ErrNetwork struct {
	Reason string
	Source string // e.g., "nostr", "dns"
}

func (e *ErrNetwork) Error() string {
	return fmt.Sprintf("network error (%s): %s", e.Source, e.Reason)
}
func (e *ErrNetwork) IsSecurityViolation() bool { return false }

// ErrIO occurs when a file system operation fails.
type ErrIO struct {
	Path   string
	Reason string
}

func (e *ErrIO) Error() string {
	return fmt.Sprintf("I/O error at '%s': %s", e.Path, e.Reason)
}
func (e *ErrIO) IsSecurityViolation() bool { return false }
