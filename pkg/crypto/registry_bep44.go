//go:build !minimal

package crypto

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	dht "github.com/anacrolix/dht/v2"
	"github.com/anacrolix/dht/v2/bep44"
	"github.com/anacrolix/dht/v2/exts/getput"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/zeebo/bencode"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
)

func init() {
	RegisterRegistry("bep44", func(conf *Config) IdentityRegistry {
		return NewBEP44Registry(conf)
	})
}

// BEP44HandlePrefix marks handles that are directly addressable via BitTorrent DHT BEP-44.
// Format: @bep44:<hex-encoded-ed25519-public-key>
const BEP44HandlePrefix = "@bep44:"

// bep44MiniRecord is the compact value stored in BEP-44 (target ≤300 bytes bencoded).
// Only multiaddrs are stored; the full IdentityRecord is fetched from the peer directly.
type bep44MiniRecord struct {
	Handle     string   `bencode:"h"`
	Multiaddrs []string `bencode:"m"`
}

// BEP44Registry implements IdentityRegistry using the BitTorrent DHT BEP-44 mutable items.
// It acts as a cold-start fallback: BEP-44 provides peer multiaddrs, the full
// IdentityRecord is then fetched from the peer via the /maknoon/id/1.0.0 stream protocol.
type BEP44Registry struct {
	conf *Config
}

func NewBEP44Registry(conf *Config) *BEP44Registry {
	if conf == nil {
		conf = GetGlobalConfig()
	}
	return &BEP44Registry{conf: conf}
}

// IsBEP44Handle returns true if the handle uses the @bep44: scheme.
func IsBEP44Handle(handle string) bool {
	return strings.HasPrefix(handle, BEP44HandlePrefix)
}

// extractEd25519FromSIGPriv extracts the Ed25519 private key from the ML-DSA-87 + Ed25519
// bundle. Ed25519 private key lives at offset mldsa87.PrivateKeySize (4896 bytes).
func extractEd25519FromSIGPriv(sigPriv []byte) (ed25519.PrivateKey, error) {
	const offset = mldsa87.PrivateKeySize
	if len(sigPriv) < offset+ed25519.PrivateKeySize {
		return nil, fmt.Errorf("SIG private key too short to contain Ed25519 key (need %d bytes, got %d)",
			offset+ed25519.PrivateKeySize, len(sigPriv))
	}
	return ed25519.PrivateKey(sigPriv[offset : offset+ed25519.PrivateKeySize]), nil
}

// extractEd25519PubFromHandle parses @bep44:<hex> and returns the 32-byte Ed25519 public key.
func extractEd25519PubFromHandle(handle string) ([32]byte, error) {
	hexStr := strings.TrimPrefix(handle, BEP44HandlePrefix)
	if len(hexStr) != 64 {
		return [32]byte{}, fmt.Errorf("invalid bep44 handle: expected 64 hex chars after prefix, got %d", len(hexStr))
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return [32]byte{}, fmt.Errorf("invalid bep44 handle hex: %w", err)
	}
	var pub [32]byte
	copy(pub[:], b)
	return pub, nil
}

// BEP44HandleFromSIGPub returns the @bep44: handle for a given ML-DSA+Ed25519 SIG public key.
func BEP44HandleFromSIGPub(sigPub []byte) (string, error) {
	const offset = mldsa87.PublicKeySize
	if len(sigPub) < offset+ed25519.PublicKeySize {
		return "", fmt.Errorf("SIG public key too short to contain Ed25519 component")
	}
	edPub := sigPub[offset : offset+ed25519.PublicKeySize]
	return fmt.Sprintf("%s%x", BEP44HandlePrefix, edPub), nil
}

func newBEP44Server() (*dht.Server, error) {
	cfg := dht.NewDefaultServerConfig()
	cfg.StartingNodes = func() ([]dht.Addr, error) {
		return dht.GlobalBootstrapAddrs("udp4")
	}
	return dht.NewServer(cfg)
}

// Publish on BEP44Registry requires access to the SIG private key.
// Use PublishWithSIGKey instead.
func (r *BEP44Registry) Publish(_ context.Context, _ *IdentityRecord) error {
	return fmt.Errorf("bep44: use PublishWithSIGKey (SIG private key required for Ed25519 signing)")
}

// PublishWithSIGKey publishes a mini-record (handle + multiaddrs) to BEP-44 using the
// Ed25519 key embedded in sigPriv. Called by IdentityPublish when opts.BEP44 is true.
func (r *BEP44Registry) PublishWithSIGKey(ctx context.Context, record *IdentityRecord, sigPriv []byte) error {
	edPriv, err := extractEd25519FromSIGPriv(sigPriv)
	if err != nil {
		return err
	}
	edPub := edPriv.Public().(ed25519.PublicKey)
	var pubKey [32]byte
	copy(pubKey[:], edPub)

	// Truncate to the first 3 multiaddrs to stay well within the 1000-byte BEP-44 limit.
	addrs := record.Multiaddrs
	if len(addrs) > 3 {
		addrs = addrs[:3]
	}

	mini := bep44MiniRecord{Handle: record.Handle, Multiaddrs: addrs}
	value, err := bencode.EncodeBytes(mini)
	if err != nil {
		return fmt.Errorf("bep44: failed to bencode mini-record: %w", err)
	}
	if len(value) > 1000 {
		return fmt.Errorf("bep44: mini-record too large (%d bytes, limit 1000)", len(value))
	}

	s, err := newBEP44Server()
	if err != nil {
		return fmt.Errorf("bep44: failed to create DHT server: %w", err)
	}
	defer s.Close()

	target := bep44.MakeMutableTarget(pubKey, nil)
	seq := time.Now().Unix()

	_, err = getput.Put(ctx, target, s, nil, func(existingSeq int64) bep44.Put {
		if existingSeq >= seq {
			seq = existingSeq + 1
		}
		put := bep44.Put{
			V:   value, // raw []byte — bep44.Put.V is interface{}
			Seq: seq,
		}
		copy(put.K[:], pubKey[:])
		put.Sign(ed25519.PrivateKey(edPriv))
		return put
	})
	if err != nil {
		return fmt.Errorf("bep44: put traversal failed: %w", err)
	}
	return nil
}

// Resolve supports @bep44:<hex-ed25519-pubkey> handles.
// For @alice-style handles it returns an error — use the libp2p DHT registry instead.
// Resolution is two-step: BEP-44 lookup → get multiaddrs → fetch full record via libp2p stream.
func (r *BEP44Registry) Resolve(ctx context.Context, handle string) (*IdentityRecord, error) {
	if !IsBEP44Handle(handle) {
		return nil, fmt.Errorf("bep44: unsupported handle %q (must be @bep44:<ed25519-hex>)", handle)
	}

	pubKey, err := extractEd25519PubFromHandle(handle)
	if err != nil {
		return nil, err
	}

	s, err := newBEP44Server()
	if err != nil {
		return nil, fmt.Errorf("bep44: failed to create DHT server: %w", err)
	}
	defer s.Close()

	target := bep44.MakeMutableTarget(pubKey, nil)
	result, _, err := getput.Get(ctx, target, s, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("bep44: item not found for handle %s: %w", handle, err)
	}

	var mini bep44MiniRecord
	rawBytes, _ := bencode.EncodeBytes(result.V) // re-encode interface{} back to []byte
	if err := bencode.DecodeBytes(rawBytes, &mini); err != nil {
		return nil, fmt.Errorf("bep44: failed to decode mini-record: %w", err)
	}

	if len(mini.Multiaddrs) == 0 {
		return nil, fmt.Errorf("bep44: no multiaddrs in record for %s (peer may be offline)", handle)
	}

	// Fetch the full IdentityRecord from the peer via libp2p stream.
	return r.fetchFullRecord(ctx, mini.Handle, mini.Multiaddrs)
}

// fetchFullRecord dials one of the given multiaddrs and requests the full IdentityRecord
// via the /maknoon/id/1.0.0 stream protocol.
func (r *BEP44Registry) fetchFullRecord(ctx context.Context, handle string, addrs []string) (*IdentityRecord, error) {
	h, err := tunnel.NewLibp2pHost()
	if err != nil {
		return nil, fmt.Errorf("bep44: failed to create libp2p host: %w", err)
	}
	defer h.Close()

	var lastErr error
	for _, addrStr := range addrs {
		maddr, err := ma.NewMultiaddr(addrStr)
		if err != nil {
			lastErr = err
			continue
		}
		ai, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			lastErr = err
			continue
		}

		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = h.Connect(dialCtx, *ai)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}

		s, err := h.NewStream(ctx, ai.ID, MaknoonIDProtocol)
		if err != nil {
			lastErr = err
			continue
		}

		rec, err := exchangeIdentityRecord(s, handle)
		if err != nil {
			lastErr = err
			continue
		}
		return rec, nil
	}

	return nil, fmt.Errorf("bep44: could not fetch full record from any peer multiaddr (last error: %v)", lastErr)
}

// exchangeIdentityRecord performs the /maknoon/id/1.0.0 client-side exchange.
func exchangeIdentityRecord(s network.Stream, handle string) (*IdentityRecord, error) {
	defer s.Close()

	req := IdentityFetchRequest{Handle: handle}
	if err := json.NewEncoder(s).Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send identity request: %w", err)
	}
	_ = s.CloseWrite()

	var rec IdentityRecord
	if err := json.NewDecoder(bufio.NewReader(s)).Decode(&rec); err != nil {
		return nil, fmt.Errorf("failed to read identity response: %w", err)
	}

	if !rec.Verify() {
		return nil, fmt.Errorf("identity record signature invalid")
	}
	return &rec, nil
}

func (r *BEP44Registry) Revoke(_ context.Context, _ string, _ []byte) error {
	return fmt.Errorf("bep44: revocation not supported")
}

var _ IdentityRegistry = (*BEP44Registry)(nil)
