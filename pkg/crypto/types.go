package crypto

import (
	"log/slog"
)

// SecretBytes is a slice of bytes that automatically redacts itself when logged or printed.
type SecretBytes []byte

// String implements fmt.Stringer.
func (s SecretBytes) String() string {
	return "[REDACTED]"
}

// LogValue implements slog.LogValuer.
func (s SecretBytes) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}

// SecretString is a string that automatically redacts itself when logged or printed.
type SecretString string

// String implements fmt.Stringer.
func (s SecretString) String() string {
	return "[REDACTED]"
}

// LogValue implements slog.LogValuer.
func (s SecretString) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}

// EncryptResult is the standard JSON output for the encrypt command.
type EncryptResult struct {
	Status       string            `json:"status"`
	Path         string            `json:"path"`
	Output       string            `json:"output,omitempty"`
	Flags        byte              `json:"flags"`
	Type         string            `json:"type"` // "symmetric" or "asymmetric"
	ProfileID    byte              `json:"profile_id"`
	Compressed   bool              `json:"compressed"`
	IsArchive    bool              `json:"is_archive"`
	IsSigned     bool              `json:"is_signed"`
	IsStealth    bool              `json:"is_stealth"`
	KEMAlgorithm string            `json:"kem_algorithm,omitempty"`
	SIGAlgorithm string            `json:"sig_algorithm,omitempty"`
	KDFDetails   string            `json:"kdf_details,omitempty"`
	SignedBy     *SignedByEvidence `json:"signed_by,omitempty"`
}

// DecryptResult is the standard JSON output for the decrypt command.
type DecryptResult struct {
	Status   string     `json:"status"`
	Output   string     `json:"output"`
	Flags    byte       `json:"flags"`
	SignedBy *TrustInfo `json:"signed_by,omitempty"`
}

// TrustInfo carries details about a verified signature.
type TrustInfo struct {
	GID       string `json:"gid"`
	IsTrusted bool   `json:"is_trusted"`
	Petname   string `json:"petname,omitempty"`
}

// SignedByEvidence provides information about the signer of a file.
type SignedByEvidence struct {
	GID       string `json:"gid"`
	IsTrusted bool   `json:"is_trusted"`
	Petname   string `json:"petname,omitempty"`
}

// IdentityResult is the standard JSON output for identity management.
type IdentityResult struct {
	Status    string   `json:"status"`
	Identity  string   `json:"identity,omitempty"`
	Secret    string   `json:"secret,omitempty"`
	BaseName  string   `json:"base_name,omitempty"`
	BasePath  string   `json:"base_path,omitempty"`
	From      string   `json:"from,omitempty"`
	To        string   `json:"to,omitempty"`
	Handle    string   `json:"handle,omitempty"`
	Registry  string   `json:"registry,omitempty"`
	Threshold int      `json:"threshold,omitempty"`
	Shares    []string `json:"shares,omitempty"`
}

// VaultResult is the standard JSON output for vault operations.
type VaultResult struct {
	Status           string           `json:"status"`
	Vault            string           `json:"vault,omitempty"`
	Secret           string           `json:"secret,omitempty"`
	Service          string           `json:"service,omitempty"`
	Deleted          string           `json:"deleted,omitempty"`
	Threshold        int              `json:"threshold,omitempty"`
	Shares           []string         `json:"shares,omitempty"`
	RecoveredEntries int              `json:"recovered_entries,omitempty"`
	Output           string           `json:"output,omitempty"`
	Entries          []VaultListEntry `json:"entries,omitempty"`
}

// VaultListEntry is a simplified vault entry for listing.
type VaultListEntry struct {
	Service  string `json:"service"`
	Username string `json:"username,omitempty"`
}

// ContactResult is the standard JSON output for contact management.
type ContactResult struct {
	Status  string `json:"status,omitempty"`
	Petname string `json:"petname,omitempty"`
	Removed string `json:"removed,omitempty"`
}

// CommonResult for simple status messages.
type CommonResult struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// HeaderInfo represents the metadata extracted from a Maknoon file header.
type HeaderInfo struct {
	Magic          string `json:"magic"`
	ProfileID      byte   `json:"profile_id"`
	Flags          byte   `json:"flags"`
	RecipientCount byte   `json:"recipient_count"`
	IsCompressed   bool   `json:"is_compressed"`
	IsArchive      bool   `json:"is_archive"`
	IsSigned       bool   `json:"is_signed"`
	IsStealth      bool   `json:"is_stealth"`
}

// DiagnosticResult provides a comprehensive state manifest of the engine and environment.
type DiagnosticResult struct {
	Timestamp string `json:"timestamp"`
	System    struct {
		OS      string `json:"os"`
		Arch    string `json:"arch"`
		Go      string `json:"go_version"`
		Version string `json:"version"`
	} `json:"system"`
	User struct {
		UID      string `json:"uid"`
		GID      string `json:"gid"`
		Username string `json:"username"`
		Home     string `json:"home_dir"`
	} `json:"user"`
	Paths struct {
		Config     string `json:"config_file"`
		MaknoonDir string `json:"maknoon_dir"`
		Keys       string `json:"keys_dir"`
		Vaults     string `json:"vaults_dir"`
	} `json:"paths"`
	Engine struct {
		Policy         string `json:"active_policy"`
		DefaultProfile byte   `json:"default_profile_id"`
		ProfileName    string `json:"default_profile_name"`
		AgentMode      bool   `json:"agent_mode_active"`
		AuditEnabled   bool   `json:"audit_enabled"`
	} `json:"engine"`
}

// NetStatusResult provides a snapshot of the P2P network and tunnel state.
type NetStatusResult struct {
	PeerID    string   `json:"peer_id"`
	Addresses []string `json:"addresses"`
	Peers     int      `json:"peer_count"`
	Protocols []string `json:"protocols"`
	Tunnel    struct {
		Active         bool   `json:"active"`
		LocalAddress   string `json:"local_address,omitempty"`
		RemoteEndpoint string `json:"remote_endpoint,omitempty"`
		HandshakeTime  string `json:"handshake_time,omitempty"`
	} `json:"tunnel"`
}

// AuditEntry represents a recorded cryptographic operation.
type AuditEntry struct {
	Timestamp string         `json:"timestamp"`
	Action    string         `json:"action"`
	Metadata  map[string]any `json:"metadata"`
	Status    string         `json:"status"`
	Error     string         `json:"error,omitempty"`
}
