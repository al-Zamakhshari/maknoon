package crypto

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anacrolix/dht/v2"
	"github.com/anacrolix/dht/v2/krpc"
)

// DHTRegistry implements IdentityRegistry using BitTorrent Mainline DHT (BEP-44).
type DHTRegistry struct {
	server *dht.Server
}

func NewDHTRegistry() (*DHTRegistry, error) {
	cfg := dht.NewDefaultServerConfig()
	// Use default bootstrap nodes
	s, err := dht.NewServer(cfg)
	if err != nil {
		return nil, err
	}
	return &DHTRegistry{server: s}, nil
}

func (r *DHTRegistry) Close() error {
	r.server.Close()
	return nil
}

func (r *DHTRegistry) Resolve(ctx context.Context, handle string) (*IdentityRecord, error) {
	// For PKarr/did:dht, the handle is usually the hex encoded Ed25519 public key.
	// e.g. "@pk:abcdef..."
	if !strings.HasPrefix(handle, "@pk:") {
		return nil, fmt.Errorf("DHT resolution requires a public key handle (e.g., @pk:<hex>)")
	}
	pkHex := strings.TrimPrefix(handle, "@pk:")
	var pk [32]byte
	n, err := fmt.Sscanf(pkHex, "%x", &pk)
	if err != nil || n != 1 {
		return nil, fmt.Errorf("invalid hex public key: %w", err)
	}

	getInput := krpc.Get{
		K: &pk,
	}

	res, err := r.server.Get(ctx, getInput)
	if err != nil {
		return nil, fmt.Errorf("DHT get failed: %w", err)
	}

	// We take the value with the highest sequence number
	var bestRecord *IdentityRecord
	var bestSeq int64 = -1

	for val := range res.Values {
		var record IdentityRecord
		// Data in DHT is JSON string
		if err := json.Unmarshal([]byte(val.V.(string)), &record); err == nil {
			if val.Seq != nil && *val.Seq > bestSeq {
				if record.Verify() {
					bestRecord = &record
					bestSeq = *val.Seq
				}
			}
		}
	}

	if bestRecord == nil {
		return nil, fmt.Errorf("no valid record found for handle %s", handle)
	}

	return bestRecord, nil
}

func (r *DHTRegistry) Publish(ctx context.Context, record *IdentityRecord) error {
	// This is tricky: we need the Ed25519 private key to sign the BEP-44 packet.
	// Since Maknoon uses ML-DSA, we'll assume the user has provided or derived an Ed25519 
	// counterpart for DHT operations.
	// For this POC, we'll check if the record contains an 'EdPriv' metadata or similar.
	// In a real implementation, we'd derive Ed25519 from the same seed as ML-DSA.
	
	return errors.New("DHT Publish requires an Ed25519 identity key (not yet implemented in POC)")
}

func (r *DHTRegistry) Revoke(ctx context.Context, handle string, proof []byte) error {
	// Revocation in DHT is done by publishing a record with 'revoked: true' and a higher sequence number.
	return errors.New("DHT Revoke not yet implemented")
}

// Note: To make this usable, we'll need to update ResolvePublicKey to try DHT if handle starts with @pk:
