package crypto

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/psanford/wormhole-william/wormhole"
)

// WormholeStreamWrapper adapts a Wormhole data stream to io.ReadWriteCloser.
// This is used to bridge the authenticated Wormhole transit pipe to the QUIC stack.
type WormholeStreamWrapper struct {
	io.ReadWriteCloser
}

// P2PStatus represents a progress update in a P2P transfer.
type P2PStatus struct {
	Phase        string // "encrypting", "connecting", "transferring", "decrypting", "success", "error"
	Code         string
	FileName     string
	BytesTotal   int64
	BytesDone    int64
	Passphrase   string
	IsAsymmetric bool
	Error        error
}

// P2PSendOptions settings for P2P sending.
type P2PSendOptions struct {
	Passphrase    []byte
	PublicKey     []byte
	Stealth       bool
	IsDirectory   bool
	RendezvousURL string
	TransitRelay  string
}

// P2PReceiveOptions settings for P2P receiving.
type P2PReceiveOptions struct {
	Passphrase    []byte
	PrivateKey    []byte
	Stealth       bool
	OutputDir     string
	RendezvousURL string
	TransitRelay  string
}

// P2PSend initiates a P2P transfer.
func (e *Engine) P2PSend(ectx *EngineContext, inputName string, r io.Reader, opts P2PSendOptions) (string, <-chan P2PStatus, error) {
	ectx = e.context(ectx)
	status := make(chan P2PStatus, 10)

	// 1. Initial Validation
	conf := e.GetConfig()
	rendezvous := opts.RendezvousURL
	if rendezvous == "" {
		rendezvous = conf.Wormhole.RendezvousURL
	}
	if err := e.ValidateWormholeURL(ectx, rendezvous); err != nil {
		return "", nil, err
	}

	// 2. Encryption (Library call)
	tmpEnc, err := os.CreateTemp("", "maknoon-p2p-send-*.makn")
	if err != nil {
		return "", nil, err
	}

	protectOpts := Options{
		Passphrase:  opts.Passphrase,
		PublicKey:   opts.PublicKey,
		Stealth:     opts.Stealth,
		Compress:    true,
		IsArchive:   opts.IsDirectory,
		Concurrency: conf.AgentLimits.MaxWorkers,
	}

	status <- P2PStatus{Phase: "encrypting"}
	_, err = e.Protect(ectx, inputName, r, tmpEnc, protectOpts)
	if err != nil {
		_ = tmpEnc.Close()
		_ = os.Remove(tmpEnc.Name())
		return "", nil, err
	}

	fi, _ := tmpEnc.Stat()
	totalBytes := fi.Size()
	if _, err := tmpEnc.Seek(0, 0); err != nil {
		return "", nil, err
	}

	// 3. Wormhole initialization
	c := wormhole.Client{
		RendezvousURL: rendezvous,
	}
	if opts.TransitRelay != "" {
		c.TransitRelayAddress = opts.TransitRelay
	} else if conf.Wormhole.TransitRelay != "" {
		c.TransitRelayAddress = conf.Wormhole.TransitRelay
	}

	fileName := filepath.Base(inputName)
	if opts.IsDirectory || !strings.HasSuffix(fileName, ".makn") {
		fileName += ".makn"
	}

	status <- P2PStatus{Phase: "connecting"}
	code, wStatus, err := c.SendFile(ectx.Context, fileName, tmpEnc)
	if err != nil {
		_ = tmpEnc.Close()
		_ = os.Remove(tmpEnc.Name())
		return "", nil, err
	}
	// Background monitor for the wormhole status
	go func() {
		defer tmpEnc.Close()
		defer os.Remove(tmpEnc.Name())
		defer close(status)

		for s := range wStatus {
			if s.Error != nil {
				status <- P2PStatus{Phase: "error", Error: s.Error}
				return
			}
			if s.OK {
				status <- P2PStatus{Phase: "success"}
				return
			}
			status <- P2PStatus{
				Phase:      "transferring",
				BytesTotal: totalBytes,
			}
		}
	}()

	return code, status, nil
}

// P2PReceive completes a P2P transfer.
func (e *Engine) P2PReceive(ectx *EngineContext, code string, opts P2PReceiveOptions) (<-chan P2PStatus, error) {
	ectx = e.context(ectx)
	status := make(chan P2PStatus, 10)
	conf := e.GetConfig()

	rendezvous := opts.RendezvousURL
	if rendezvous == "" {
		rendezvous = conf.Wormhole.RendezvousURL
	}
	if err := e.ValidateWormholeURL(ectx, rendezvous); err != nil {
		return nil, err
	}

	c := wormhole.Client{
		RendezvousURL: rendezvous,
	}
	if opts.TransitRelay != "" {
		c.TransitRelayAddress = opts.TransitRelay
	} else if conf.Wormhole.TransitRelay != "" {
		c.TransitRelayAddress = conf.Wormhole.TransitRelay
	}

	status <- P2PStatus{Phase: "connecting"}
	msg, err := c.Receive(ectx.Context, code)
	if err != nil {
		return nil, err
	}
	if msg.Type != wormhole.TransferFile {
		return nil, fmt.Errorf("unexpected message type: %v", msg.Type)
	}

	go func() {
		defer close(status)

		tmpFile, err := os.CreateTemp("", "maknoon-p2p-recv-*.makn")
		if err != nil {
			status <- P2PStatus{Phase: "error", Error: err}
			return
		}
		defer tmpFile.Close()
		defer os.Remove(tmpFile.Name())
		status <- P2PStatus{
			Phase:      "transferring",
			FileName:   msg.Name,
			BytesTotal: msg.TransferBytes64,
		}

		if _, err := io.Copy(tmpFile, msg); err != nil {
			status <- P2PStatus{Phase: "error", Error: err}
			return
		}

		if _, err := tmpFile.Seek(0, 0); err != nil {
			status <- P2PStatus{Phase: "error", Error: err}
			return
		}

		status <- P2PStatus{Phase: "decrypting"}

		finalOut := opts.OutputDir
		if finalOut == "" {
			finalOut = strings.TrimSuffix(filepath.Base(msg.Name), ".makn")
		}

		unprotectOpts := Options{
			Passphrase:      opts.Passphrase,
			LocalPrivateKey: opts.PrivateKey,
			Stealth:         opts.Stealth,
			Concurrency:     conf.AgentLimits.MaxWorkers,
		}

		_, err = e.Unprotect(ectx, tmpFile, nil, finalOut, unprotectOpts)
		if err != nil {
			status <- P2PStatus{Phase: "error", Error: err}
			return
		}

		status <- P2PStatus{Phase: "success", FileName: finalOut}
	}()

	return status, nil
}
