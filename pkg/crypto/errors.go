package crypto

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
)

// FormatMCPError converts a Go error into a structured MCP ToolResultError.
// The JSON payload always contains "error" (human message) and "tool" (originating tool).
// Additional fields are set based on the concrete error type so that AI agents
// can branch on "type" without parsing error strings:
//
//   - "authentication_failure"      — wrong passphrase, no matching recipient key,
//     signature verification failed; agent hint: "check key/passphrase"
//   - "security_policy_violation"   — capability or path blocked by active policy
//   - "format_error"                — file is not a valid .makn archive (corrupt/wrong format)
//   - "crypto_failure"              — MAC mismatch or low-level AEAD failure (file tampered?)
//   - "io_error"                    — file not found or permission denied
//   - "network_error"               — registry relay unreachable
func FormatMCPError(err error, tool string) (*mcp.CallToolResult, error) {
	resp := map[string]interface{}{"error": err.Error(), "tool": tool}

	switch {
	case errors.As(err, new(*ErrPolicyViolation)):
		resp["type"] = "security_policy_violation"
		resp["is_security_violation"] = true
		resp["hint"] = "operation blocked by the active security policy"

	case errors.As(err, new(*ErrAuthentication)):
		resp["type"] = "authentication_failure"
		resp["hint"] = "check that the passphrase is correct and the private key matches a recipient in the file"

	case errors.As(err, new(*ErrFormat)):
		resp["type"] = "format_error"
		resp["hint"] = "the file does not appear to be a valid .makn archive — it may be corrupt or in the wrong format"

	case errors.As(err, new(*ErrCrypto)):
		resp["type"] = "crypto_failure"
		resp["hint"] = "ciphertext authentication failed — the file may have been tampered with or decrypted with the wrong key"

	case errors.As(err, new(*ErrIO)):
		resp["type"] = "io_error"
		resp["hint"] = "check that the file path exists and is readable"

	case errors.As(err, new(*ErrNetwork)):
		resp["type"] = "network_error"
		resp["hint"] = "check network connectivity and retry; use 'maknoon registry health' to diagnose relay reachability"
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
	Reason     string
	Path       string
	Capability string
	PolicyName string
}

func (e *ErrPolicyViolation) Error() string {
	msg := "security policy violation"
	if e.PolicyName != "" {
		msg = fmt.Sprintf("security policy '%s' violation", e.PolicyName)
	}
	if e.Capability != "" {
		msg = fmt.Sprintf("%s: capability '%s' is prohibited", msg, e.Capability)
	} else if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}

	if e.Path != "" {
		msg = fmt.Sprintf("%s at '%s'", msg, e.Path)
	}
	return msg
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

// isErrAuthentication unwraps err as *ErrAuthentication, setting target if non-nil. Returns true on match.
func isErrAuthentication(err error, target **ErrAuthentication) bool {
	if err == nil {
		return false
	}
	var ae *ErrAuthentication
	if errors.As(err, &ae) {
		if target != nil {
			*target = ae
		}
		return true
	}
	return false
}

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
