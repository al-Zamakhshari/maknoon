package crypto

import (
	"crypto/rand"
	"encoding/hex"
)

// P2PStatus represents a progress update in a P2P transfer.
type P2PStatus struct {
	Phase        string // "encrypting", "connecting", "transferring", "decrypting", "success", "error"
	Code         string
	TraceID      string
	Addrs        []string
	FileName     string
	BytesTotal   int64
	BytesDone    int64
	Passphrase   string
	IsAsymmetric bool
	Error        error
}

// GenerateTraceID creates a unique correlation ID for cross-node tracing.
func GenerateTraceID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

// P2PSendOptions settings for P2P sending.
type P2PSendOptions struct {
	Passphrase  SecretBytes
	PublicKey   []byte
	Stealth     *bool
	IsDirectory bool
	P2PMode     bool   // Always true in v3.1
	To          string // Remote PeerID or @petname
	TraceID     string
}

// P2PReceiveOptions settings for P2P receiving.
type P2PReceiveOptions struct {
	Passphrase SecretBytes
	PrivateKey SecretBytes
	Stealth    *bool
	OutputDir  string
	P2PMode    bool // Always true in v3.1
	TraceID    string
}

// P2PSend initiates a libp2p P2P transfer.

// P2PReceive completes a libp2p P2P transfer.
