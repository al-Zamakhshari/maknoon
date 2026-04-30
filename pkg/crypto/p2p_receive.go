package crypto

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
)

// runLibp2pReceive handles the receiver side of a libp2p file transfer.
func (e *Engine) runLibp2pReceive(ectx *EngineContext, h host.Host, opts P2PReceiveOptions, status chan P2PStatus) {
	defer close(status)

	h.SetStreamHandler(P2PSendProtocol, func(stream network.Stream) {
		defer stream.Close()
		slog.Info("p2p: incoming file transfer", "from", stream.Conn().RemotePeer())

		// 1. Read Header
		header, err := P2PReadProtocolHeader(stream)
		if err != nil {
			e.Logger.Error("p2p: failed to read header", "err", err)
			return
		}

		e.Logger.Debug("P2P transfer received", "trace_id", header.TraceID, "file", header.Name, "size", header.Size)

		status <- P2PStatus{
			Phase:      "transferring",
			FileName:   header.Name,
			BytesTotal: header.Size,
			TraceID:    header.TraceID,
		}

		// 2. Download to temp file
		tmpFile, err := os.CreateTemp("", "maknoon-p2p-recv-*.makn")
		if err != nil {
			status <- P2PStatus{Phase: "error", Error: err}
			return
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		if _, err := io.Copy(tmpFile, stream); err != nil {
			status <- P2PStatus{Phase: "error", Error: err}
			return
		}

		// 3. Decrypt
		if _, err := tmpFile.Seek(0, 0); err != nil {
			status <- P2PStatus{Phase: "error", Error: err}
			return
		}

		status <- P2PStatus{Phase: "decrypting"}

		finalOut := opts.OutputDir
		if finalOut == "" {
			finalOut = strings.TrimSuffix(filepath.Base(header.Name), ".makn")
		}

		_, err = e.P2PUnpackMessage(ectx, tmpFile, nil, finalOut, opts)
		if err != nil {
			status <- P2PStatus{Phase: "error", Error: err}
			return
		}

		status <- P2PStatus{Phase: "success", FileName: finalOut}
	})

	// Wait for context to end
	<-ectx.Done()
}
