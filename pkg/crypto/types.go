package crypto

// EncryptResult is the standard JSON output for the encrypt command.
type EncryptResult struct {
	Status       string            `json:"status"`
	Path         string            `json:"path"`
	Output       string            `json:"output,omitempty"`
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
