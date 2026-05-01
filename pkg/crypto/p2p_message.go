package crypto

import (
	"encoding/json"
	"fmt"
	"io"
)

// P2PMessageHeader defines the universal header for any Maknoon P2P transport.
type P2PMessageHeader struct {
	TraceID string `json:"trace_id,omitempty"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
}

// P2PPackMessage prepares a secure payload for P2P transmission.
func (e *Engine) P2PPackMessage(ectx *EngineContext, name string, r io.Reader, w io.Writer, opts P2PSendOptions) error {
	protectOpts := Options{
		Passphrase:  opts.Passphrase,
		PublicKey:   opts.PublicKey,
		Stealth:     opts.Stealth,
		Compress:    BoolPtr(true),
		IsArchive:   opts.IsDirectory,
		Concurrency: IntPtr(e.Config.AgentLimits.MaxWorkers),
	}

	_, err := e.Protect(ectx, name, r, w, protectOpts)
	return err
}

// P2PUnpackMessage decapsulates and decrypts a received P2P payload.
func (e *Engine) P2PUnpackMessage(ectx *EngineContext, r io.Reader, w io.Writer, outputDir string, opts P2PReceiveOptions) (DecryptResult, error) {
	unprotectOpts := Options{
		Passphrase:      opts.Passphrase,
		LocalPrivateKey: opts.PrivateKey,
		Stealth:         opts.Stealth,
		Concurrency:     IntPtr(e.Config.AgentLimits.MaxWorkers),
	}

	return e.Unprotect(ectx, r, w, outputDir, unprotectOpts)
}

// P2PWriteProtocolHeader writes the JSON header to a P2P stream.
func P2PWriteProtocolHeader(w io.Writer, name string, size int64, traceID string) error {
	header := P2PMessageHeader{TraceID: traceID, Name: name, Size: size}
	return json.NewEncoder(w).Encode(header)
}

// P2PReadProtocolHeader reads the JSON header from a P2P stream.
func P2PReadProtocolHeader(r io.Reader) (*P2PMessageHeader, error) {
	var h P2PMessageHeader
	if err := json.NewDecoder(r).Decode(&h); err != nil {
		return nil, fmt.Errorf("failed to decode P2P header: %w", err)
	}
	return &h, nil
}
