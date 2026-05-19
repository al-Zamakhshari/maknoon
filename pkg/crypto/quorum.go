package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateTraceID returns a random 8-byte hex trace correlation ID.
func GenerateTraceID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// QuorumAction identifies the operation requiring multi-party approval.
type QuorumAction string

const (
	ActionVaultUnlock QuorumAction = "vault_unlock"
	ActionConfigAdmin QuorumAction = "config_admin"
)

// QuorumResponse holds one peer's approval decision.
type QuorumResponse struct {
	PeerID   string
	Approved bool
	Payload  []byte
}

// QuorumRequest sends an approval request to the specified peers and collects responses.
// With P2P transport removed, quorum requests are not supported and return an error.
func (e *Engine) QuorumRequest(_ *EngineContext, _ string, peers []string, action QuorumAction, resource, _ string) ([]QuorumResponse, error) {
	return nil, fmt.Errorf("quorum request for %s on %q requires P2P transport (removed); configure manual approval for %d peers", action, resource, len(peers))
}
