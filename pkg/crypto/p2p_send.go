package crypto

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

const P2PSendProtocol = "/maknoon/send/1.0.0"

// runLibp2pSend handles the sender side of a libp2p file transfer.
func (e *Engine) runLibp2pSend(ectx *EngineContext, inputName string, r io.Reader, h host.Host, target string, opts P2PSendOptions, status chan P2PStatus) {
	defer close(status)

	var pID peer.ID
	var err error

	// Try parsing as Multiaddr first
	if ma, maErr := multiaddr.NewMultiaddr(target); maErr == nil {
		info, infoErr := peer.AddrInfoFromP2pAddr(ma)
		if infoErr == nil {
			pID = info.ID
			if err := h.Connect(ectx.Context, *info); err != nil {
				status <- P2PStatus{Phase: "error", Error: fmt.Errorf("failed to connect to multiaddr: %w", err)}
				return
			}
		} else {
			pID, err = peer.Decode(target)
		}
	} else {
		pID, err = peer.Decode(target)
	}

	if err != nil {
		status <- P2PStatus{Phase: "error", Error: fmt.Errorf("invalid PeerID: %w", err)}
		return
	}

	status <- P2PStatus{Phase: "connecting"}
	stream, err := h.NewStream(ectx.Context, pID, P2PSendProtocol)
	if err != nil {
		status <- P2PStatus{Phase: "error", Error: fmt.Errorf("failed to open stream: %w", err)}
		return
	}
	defer stream.Close()

	// 1. Prepare encrypted payload
	status <- P2PStatus{Phase: "encrypting"}
	tmpEnc, err := os.CreateTemp("", "maknoon-p2p-send-*.makn")
	if err != nil {
		status <- P2PStatus{Phase: "error", Error: err}
		return
	}
	defer os.Remove(tmpEnc.Name())
	defer tmpEnc.Close()

	if err := e.P2PPackMessage(ectx, inputName, r, tmpEnc, opts); err != nil {
		status <- P2PStatus{Phase: "error", Error: err}
		return
	}

	fi, _ := tmpEnc.Stat()
	totalBytes := fi.Size()
	if _, err := tmpEnc.Seek(0, 0); err != nil {
		status <- P2PStatus{Phase: "error", Error: err}
		return
	}

	// 2. Send Header
	traceID := GenerateTraceID()
	e.Logger.Debug("P2P transfer starting", "trace_id", traceID, "file", inputName, "target", target)

	if err := P2PWriteProtocolHeader(stream, filepath.Base(inputName)+".makn", totalBytes, traceID); err != nil {
		status <- P2PStatus{Phase: "error", Error: fmt.Errorf("failed to send header: %w", err)}
		return
	}

	// 3. Stream Data
	status <- P2PStatus{Phase: "transferring", BytesTotal: totalBytes}
	if _, err := io.Copy(stream, tmpEnc); err != nil {
		status <- P2PStatus{Phase: "error", Error: fmt.Errorf("transfer failed: %w", err)}
		return
	}

	status <- P2PStatus{Phase: "success"}
}
