package crypto

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
)

func (e *Engine) runLibp2pFragmentSend(ectx *EngineContext, inputName string, r io.Reader, h host.Host, targets string, opts P2PSendOptions, status chan P2PStatus) {
	defer close(status)
	defer h.Close()

	targetList := strings.Split(targets, ",")
	totalShards := opts.DataShards + opts.ParityShards

	if len(targetList) < totalShards {
		status <- P2PStatus{Phase: "error", Error: fmt.Errorf("insufficient targets for fragmentation: need %d, got %d", totalShards, len(targetList))}
		return
	}

	status <- P2PStatus{Phase: "connecting"}

	writers := make([]io.WriteCloser, totalShards)
	var wg sync.WaitGroup
	var connErr error
	var mu sync.Mutex

	for i := 0; i < totalShards; i++ {
		wg.Add(1)
		go func(idx int, target string) {
			defer wg.Done()
			stream, err := e.connectToPeer(ectx, h, target, P2PSendProtocol)
			if err != nil {
				mu.Lock()
				connErr = err
				mu.Unlock()
				return
			}

			// Send P2P Header to each peer
			// For fragments, we use a specialized name
			fragName := fmt.Sprintf("%s.shard_%03d.maknf", inputName, idx)
			if err := P2PWriteProtocolHeader(stream, fragName, 0, opts.TraceID); err != nil {
				stream.Close()
				return
			}

			mu.Lock()
			writers[idx] = stream
			mu.Unlock()
		}(i, targetList[i])
	}

	wg.Wait()
	if connErr != nil {
		status <- P2PStatus{Phase: "error", Error: connErr}
		return
	}

	// 1. Prepare input stream
	status <- P2PStatus{Phase: "encrypting"}

	// We need to determine the total size if possible
	var totalSize int64
	if inputName != "-" && inputName != "" {
		if fi, err := os.Stat(inputName); err == nil {
			totalSize = fi.Size()
		}
	}

	// Create FragmentWriter with P2P streams
	fOpts := FragmentOptions{
		DataShards:   opts.DataShards,
		ParityShards: opts.ParityShards,
		OriginalSize: totalSize,
	}

	fw, err := NewFragmentWriterWithWriters(fOpts, writers)
	if err != nil {
		status <- P2PStatus{Phase: "error", Error: err}
		return
	}
	defer fw.Close()

	// 2. Wrap input with encryption if needed
	// For P2P, we usually pack the message which handles encryption
	// But P2PPackMessage writes to a single Writer.
	// We can pass FragmentWriter to P2PPackMessage!

	status <- P2PStatus{Phase: "transferring"}
	if err := e.P2PPackMessage(ectx, inputName, r, fw, opts); err != nil {
		status <- P2PStatus{Phase: "error", Error: err}
		return
	}

	// Wait for flushes
	time.Sleep(1 * time.Second)
	status <- P2PStatus{Phase: "success"}
}

func (e *Engine) runLibp2pFragmentReceive(ectx *EngineContext, baseName string, h host.Host, opts P2PReceiveOptions, status chan P2PStatus) {
	defer close(status)
	defer h.Close()

	targetList := strings.Split(opts.From, ",")
	if len(targetList) == 0 {
		status <- P2PStatus{Phase: "error", Error: fmt.Errorf("no sources specified for fragment retrieval")}
		return
	}

	status <- P2PStatus{Phase: "connecting"}

	// Create a temporary directory for fragments
	tmpDir, err := os.MkdirTemp("", "maknoon-fragments-*")
	if err != nil {
		status <- P2PStatus{Phase: "error", Error: err}
		return
	}
	defer os.RemoveAll(tmpDir)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var fetchErr error
	fetchedCount := 0

	for i, target := range targetList {
		wg.Add(1)
		go func(idx int, t string) {
			defer wg.Done()
			stream, err := e.connectToPeer(ectx, h, t, P2PFragmentProtocol)
			if err != nil {
				return
			}
			defer stream.Close()

			// Send Request
			req := P2PFragmentRequest{
				FileName: baseName,
				ShardIdx: idx,
			}
			if err := json.NewEncoder(stream).Encode(req); err != nil {
				return
			}

			// Read Fragment Header
			header, err := P2PReadProtocolHeader(stream)
			if err != nil {
				return
			}

			// Save to tmpDir
			f, err := os.Create(filepath.Join(tmpDir, header.Name))
			if err != nil {
				return
			}
			defer f.Close()

			if _, err := io.Copy(f, stream); err != nil {
				return
			}

			mu.Lock()
			fetchedCount++
			mu.Unlock()
		}(i, target)
	}

	wg.Wait()
	if fetchErr != nil {
		status <- P2PStatus{Phase: "error", Error: fetchErr}
		return
	}

	if fetchedCount == 0 {
		status <- P2PStatus{Phase: "error", Error: fmt.Errorf("failed to retrieve any fragments from %d sources", len(targetList))}
		return
	}

	status <- P2PStatus{Phase: "decrypting"}

	finalOut := opts.OutputDir
	if finalOut == "" {
		finalOut = strings.TrimSuffix(filepath.Base(baseName), ".makn")
	}

	// Reassemble
	// We need the signing key if we want to verify.
	// For now, let's assume we use the identity's SIGPub.
	var authorizedKey []byte
	// TODO: Get authorizedKey from somewhere (e.g. sender's public key)

	outF, err := os.Create(finalOut)
	if err != nil {
		status <- P2PStatus{Phase: "error", Error: err}
		return
	}
	defer outF.Close()

	if err := ReassembleFragments(tmpDir, outF, authorizedKey); err != nil {
		status <- P2PStatus{Phase: "error", Error: err}
		return
	}

	status <- P2PStatus{Phase: "success", FileName: finalOut}
}

// RegisterFragmentHandler enables this node to serve fragments to other peers.
func (e *Engine) RegisterFragmentHandler(h host.Host, storageDir string) {
	h.SetStreamHandler(P2PFragmentProtocol, func(stream network.Stream) {
		defer stream.Close()

		var req P2PFragmentRequest
		if err := json.NewDecoder(stream).Decode(&req); err != nil {
			return
		}

		// Try to find the fragment
		// 1. Check in storageDir
		pattern := fmt.Sprintf("%s.shard_%03d.maknf", req.FileName, req.ShardIdx)
		matches, _ := filepath.Glob(filepath.Join(storageDir, pattern))
		if len(matches) == 0 {
			// Try without baseName if FileName is a path
			matches, _ = filepath.Glob(filepath.Join(storageDir, filepath.Base(pattern)))
		}

		if len(matches) > 0 {
			f, err := os.Open(matches[0])
			if err != nil {
				return
			}
			defer f.Close()

			fi, _ := f.Stat()
			if err := P2PWriteProtocolHeader(stream, filepath.Base(matches[0]), fi.Size(), "fragment-pull"); err != nil {
				return
			}

			io.Copy(stream, f)
		}
	})
}

func (e *Engine) connectToPeer(ectx *EngineContext, h host.Host, target string, protocol protocol.ID) (network.Stream, error) {
	var pID peer.ID
	var err error

	target = strings.TrimSpace(target)

	// Try resolving @petname
	if strings.HasPrefix(target, "@") {
		if err := e.ensureContacts(); err == nil {
			if c, err2 := e.Contacts.Get(target); err2 == nil {
				target = c.PeerID
			}
		}
	}

	// Try parsing as Multiaddr
	if ma, maErr := multiaddr.NewMultiaddr(target); maErr == nil {
		info, infoErr := peer.AddrInfoFromP2pAddr(ma)
		if infoErr == nil {
			pID = info.ID
			if err := h.Connect(ectx.Context, *info); err != nil {
				return nil, err
			}
		} else {
			pID, err = peer.Decode(target)
		}
	} else {
		pID, err = peer.Decode(target)
	}

	if err != nil {
		return nil, fmt.Errorf("invalid PeerID '%s': %w", target, err)
	}

	return h.NewStream(ectx.Context, pID, protocol)
}
