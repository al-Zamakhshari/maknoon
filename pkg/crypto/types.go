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

// IdentityInfoResult provides detailed metadata about a local identity.
type IdentityInfoResult struct {
	Name     string `json:"name"`
	KEMPub   string `json:"kem_pub,omitempty"`
	SIGPub   string `json:"sig_pub,omitempty"`
	NostrPub string `json:"nostr_pub,omitempty"`
	PeerID   string `json:"peer_id,omitempty"`
}

// VaultResult is the standard JSON output for vault operations.
type VaultResult struct {
	Status           string           `json:"status"`
	Vault            string           `json:"vault,omitempty"`
	Secret           string           `json:"secret,omitempty"`
	Service          string           `json:"service,omitempty"`
	Deleted          string           `json:"deleted,omitempty"`
	From             string           `json:"from,omitempty"`
	To               string           `json:"to,omitempty"`
	Threshold        int              `json:"threshold,omitempty"`
	Shares           []string         `json:"shares,omitempty"`
	RecoveredEntries int              `json:"recovered_entries,omitempty"`
	Output           string           `json:"output,omitempty"`
	Entries          []VaultListEntry `json:"entries,omitempty"`
}

// SignResult is the standard JSON output for digital signatures.
type SignResult struct {
	Status        string `json:"status"`
	SignaturePath string `json:"signature_path,omitempty"`
}

// VerifyResult is the standard JSON output for signature verification.
type VerifyResult struct {
	Status   string `json:"status"`
	Verified bool   `json:"verified"`
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

// P2PResult is the standard JSON output for P2P operations.
type P2PResult struct {
	Status string   `json:"status"`
	PeerID string   `json:"peer_id,omitempty"`
	Path   string   `json:"path,omitempty"`
	Addrs  []string `json:"addrs,omitempty"`
}

// ChatResult is the standard JSON output for chat session initiation.
type ChatResult struct {
	Status string   `json:"status"`
	PeerID string   `json:"peer_id"`
	Addrs  []string `json:"addrs"`
}

// ProfileResult is the standard JSON output for profile management.
type ProfileResult struct {
	Status  string          `json:"status"`
	Name    string          `json:"name,omitempty"`
	ID      byte            `json:"id,omitempty"`
	Removed string          `json:"removed,omitempty"`
	Profile *DynamicProfile `json:"profile,omitempty"`
}

// ProfileInfo provides metadata about a cryptographic profile.
type ProfileInfo struct {
	Name        string          `json:"name"`
	ID          byte            `json:"id"`
	Description string          `json:"description,omitempty"`
	Details     *DynamicProfile `json:"details,omitempty"`
}

// ProfileListResult is the structured output for listing profiles.
type ProfileListResult struct {
	Profiles []ProfileInfo `json:"profiles"`
}

// GenResult is the structured output for generation tools.
type GenResult struct {
	Password   string `json:"password,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

// ResolveResult is the structured output for identity resolution.
type ResolveResult struct {
	PublicKey string `json:"public_key"`
}

// ConfigResult is the standard JSON output for configuration management.
type ConfigResult struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// NetworkResult is the standard JSON output for network management.
type NetworkResult struct {
	Status string `json:"status"`
}

// CommonResult for simple status messages.
type CommonResult struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// HeaderInfo represents the metadata extracted from a Maknoon file header.
type HeaderInfo struct {
	Magic          string `json:"magic"`
	Type           string `json:"type"` // "symmetric", "asymmetric", or "stealth"
	ProfileID      byte   `json:"profile_id"`
	Flags          byte   `json:"flags"`
	RecipientCount byte   `json:"recipient_count"`
	Compressed     bool   `json:"compressed"`
	IsArchive      bool   `json:"is_archive"`
	IsSigned       bool   `json:"is_signed"`
	IsStealth      bool   `json:"is_stealth"`
	KEMAlgorithm   string `json:"kem_algorithm,omitempty"`
	SIGAlgorithm   string `json:"sig_algorithm,omitempty"`
	KDFDetails     string `json:"kdf_details,omitempty"`
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
	Performance PerformanceConfig `json:"performance"`
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
