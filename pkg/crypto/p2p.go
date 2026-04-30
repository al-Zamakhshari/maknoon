package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"io"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/libp2p/go-libp2p"
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
	Passphrase  []byte
	PublicKey   []byte
	Stealth     bool
	IsDirectory bool
	P2PMode     bool   // Always true in v3.1
	To          string // Remote PeerID or @petname
}

// P2PReceiveOptions settings for P2P receiving.
type P2PReceiveOptions struct {
	Passphrase []byte
	PrivateKey []byte
	Stealth    bool
	OutputDir  string
	P2PMode    bool // Always true in v3.1
}

// P2PSend initiates a libp2p P2P transfer.
func (e *Engine) P2PSend(ectx *EngineContext, identityName string, inputName string, r io.Reader, opts P2PSendOptions) (string, <-chan P2PStatus, error) {
	ectx = e.context(ectx)
	status := make(chan P2PStatus, 10)

	// 1. Load active identity
	idName := identityName
	if idName == "" {
		idName = e.GetConfig().DefaultIdentity
	}
	if idName == "" {
		idName = "default"
	}

	id, err := e.Identities.LoadIdentity(idName, nil, "", false)
	if err != nil {
		return "", nil, err
	}
	priv, err := id.AsLibp2pKey()
	if err != nil {
		return "", nil, err
	}
	h, err := tunnel.NewLibp2pHost(libp2p.Identity(priv))
	if err != nil {
		return "", nil, err
	}
	go e.runLibp2pSend(ectx, inputName, r, h, opts.To, opts, status)
	return h.ID().String(), status, nil
}

// P2PReceive completes a libp2p P2P transfer.
func (e *Engine) P2PReceive(ectx *EngineContext, identityName string, code string, opts P2PReceiveOptions) (<-chan P2PStatus, error) {
	ectx = e.context(ectx)
	status := make(chan P2PStatus, 10)

	// 1. Load active identity
	idName := identityName
	if idName == "" {
		idName = e.GetConfig().DefaultIdentity
	}
	if idName == "" {
		idName = "default"
	}

	id, err := e.Identities.LoadIdentity(idName, nil, "", false)
	if err != nil {
		return nil, err
	}
	priv, err := id.AsLibp2pKey()
	if err != nil {
		return nil, err
	}
	h, err := tunnel.NewLibp2pHost(libp2p.Identity(priv))
	if err != nil {
		return nil, err
	}
	go e.runLibp2pReceive(ectx, h, opts, status)

	var addrs []string
	for _, a := range h.Addrs() {
		addrs = append(addrs, a.String()+"/p2p/"+h.ID().String())
	}

	// We return our ID in the "connecting" phase so the user can share it
	status <- P2PStatus{Phase: "connecting", Code: h.ID().String(), Addrs: addrs}
	return status, nil
}

func (e *Engine) ValidateWormholeURL(ectx *EngineContext, url string) error {
	return nil // Deprecated
}
