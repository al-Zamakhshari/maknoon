package crypto

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	record "github.com/libp2p/go-libp2p-record"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
)

func init() {
	RegisterRegistry("libp2p", func(conf *Config) IdentityRegistry {
		return NewLibP2PDHTRegistry(conf)
	})
}

const libp2pDHTNamespace = "/maknoon/id/"

// libp2pIDValidator verifies IdentityRecord values stored in the DHT.
type libp2pIDValidator struct{}

func (libp2pIDValidator) Validate(_ string, value []byte) error {
	var rec IdentityRecord
	if err := json.Unmarshal(value, &rec); err != nil {
		return fmt.Errorf("invalid identity record: %w", err)
	}
	if !rec.Verify() {
		return fmt.Errorf("identity record ML-DSA signature invalid")
	}
	return nil
}

func (libp2pIDValidator) Select(_ string, values [][]byte) (int, error) {
	best := 0
	var bestTime time.Time
	for i, v := range values {
		var rec IdentityRecord
		if err := json.Unmarshal(v, &rec); err == nil && rec.Timestamp.After(bestTime) {
			best = i
			bestTime = rec.Timestamp
		}
	}
	return best, nil
}

// LibP2PDHTRegistry implements IdentityRegistry using the libp2p Kademlia DHT.
// Records persist in the DHT for approximately 24 hours before requiring republication.
type LibP2PDHTRegistry struct {
	bootstrapPeers []peer.AddrInfo
}

// LibP2PRegistryConfig holds bootstrap peer configuration for the libp2p DHT registry.
type LibP2PRegistryConfig struct {
	BootstrapPeers []string `json:"bootstrap_peers" mapstructure:"bootstrap_peers"`
}

func NewLibP2PDHTRegistry(conf *Config) *LibP2PDHTRegistry {
	if conf == nil {
		conf = GetGlobalConfig()
	}
	var peers []peer.AddrInfo
	for _, addrStr := range conf.LibP2P.BootstrapPeers {
		maddr, err := ma.NewMultiaddr(addrStr)
		if err != nil {
			continue
		}
		ai, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			continue
		}
		peers = append(peers, *ai)
	}
	if len(peers) == 0 {
		peers = dht.GetDefaultBootstrapPeerAddrInfos()
	}
	return &LibP2PDHTRegistry{bootstrapPeers: peers}
}

func dhtKey(handle string) string {
	// Strip leading @ if present; the namespace prefix differentiates the key space.
	name := handle
	if len(name) > 0 && name[0] == '@' {
		name = name[1:]
	}
	return libp2pDHTNamespace + name
}

func (r *LibP2PDHTRegistry) newDHTClient(ctx context.Context) (*dht.IpfsDHT, func(), error) {
	h, err := tunnel.NewLibp2pHost()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}
	cleanup := func() { h.Close() }

	// Connect to bootstrap peers (best-effort, timeouts are fine).
	for _, ai := range r.bootstrapPeers {
		dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = h.Connect(dialCtx, ai)
		cancel()
	}

	kdht, err := dht.New(ctx, h,
		dht.Mode(dht.ModeClient),
		dht.BootstrapPeers(r.bootstrapPeers...),
		dht.NamespacedValidator("maknoon", libp2pIDValidator{}),
	)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to create DHT: %w", err)
	}

	fullCleanup := func() {
		kdht.Close()
		h.Close()
	}

	if err := kdht.Bootstrap(ctx); err != nil {
		fullCleanup()
		return nil, nil, fmt.Errorf("DHT bootstrap failed: %w", err)
	}

	// Allow routing table to populate before put/get operations.
	select {
	case <-time.After(3 * time.Second):
	case <-ctx.Done():
		fullCleanup()
		return nil, nil, ctx.Err()
	}

	return kdht, fullCleanup, nil
}

func (r *LibP2PDHTRegistry) Publish(ctx context.Context, record *IdentityRecord) error {
	kdht, cleanup, err := r.newDHTClient(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	value, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal identity record: %w", err)
	}

	if err := kdht.PutValue(ctx, dhtKey(record.Handle), value); err != nil {
		return fmt.Errorf("DHT PutValue failed: %w", err)
	}
	return nil
}

func (r *LibP2PDHTRegistry) Resolve(ctx context.Context, handle string) (*IdentityRecord, error) {
	kdht, cleanup, err := r.newDHTClient(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	value, err := kdht.GetValue(ctx, dhtKey(handle))
	if err != nil {
		return nil, fmt.Errorf("identity not found in libp2p DHT for %s: %w", handle, err)
	}

	var rec IdentityRecord
	if err := json.Unmarshal(value, &rec); err != nil {
		return nil, fmt.Errorf("failed to parse identity record: %w", err)
	}
	if !rec.Verify() {
		return nil, fmt.Errorf("identity record signature verification failed for %s", handle)
	}
	return &rec, nil
}

func (r *LibP2PDHTRegistry) Revoke(_ context.Context, _ string, _ []byte) error {
	return fmt.Errorf("libp2p DHT revocation requires republishing with Revoked=true via IdentityPublish")
}

// Ensure LibP2PDHTRegistry satisfies the interface at compile time.
var _ IdentityRegistry = (*LibP2PDHTRegistry)(nil)

// suppress unused import warning — record.NamespacedValidator is used via dht.NamespacedValidator
var _ record.Validator = libp2pIDValidator{}
