package crypto

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// MaknoonIDProtocol is the libp2p protocol for identity record exchange.
const MaknoonIDProtocol = protocol.ID("/maknoon/id/1.0.0")

// IdentityFetchRequest is sent by clients over the /maknoon/id/1.0.0 stream.
type IdentityFetchRequest struct {
	Handle string `json:"handle"`
}

// RegisterIdentityStreamHandler installs the /maknoon/id/1.0.0 handler on h.
// When a peer requests an identity record, the handler looks it up via the
// provided IdentityManager and returns the full IdentityRecord as JSON.
func RegisterIdentityStreamHandler(h host.Host, mgr *IdentityManager) {
	h.SetStreamHandler(MaknoonIDProtocol, func(s network.Stream) {
		defer s.Reset()

		var req IdentityFetchRequest
		if err := json.NewDecoder(s).Decode(&req); err != nil {
			slog.Debug("identity stream: failed to decode request", "err", err)
			return
		}

		// Try to resolve the record from the multi-registry.
		reg := NewIdentityRegistry(mgr.Config)
		rec, err := reg.Resolve(context.Background(), req.Handle)
		if err != nil {
			slog.Debug("identity stream: resolve failed", "handle", req.Handle, "err", err)
			return
		}

		if err := json.NewEncoder(s).Encode(rec); err != nil {
			slog.Debug("identity stream: failed to write response", "err", err)
		}
	})
}
