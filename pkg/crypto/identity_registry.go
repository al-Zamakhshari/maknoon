package crypto

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// MultiaddrsProvider can return the node's current P2P multiaddresses.
type MultiaddrsProvider interface {
	Multiaddrs(ctx context.Context, identityName string) []string
}

// IdentityPublishOptions settings for publishing an identity.
type IdentityPublishOptions struct {
	Name       string // Local identity name
	Passphrase string // Passphrase to unlock local identity
	Local      bool   // Add to local contacts only
	LibP2P     bool   // Deprecated: libp2p-kad-dht was removed; ignored
	DNS        bool   // Generate DNS TXT record instructions
	Desec      bool   // Publish to DNS via deSEC.io API
	DesecToken string // deSEC API token
	WKD        bool   // Publish to HTTPS static file (Web Key Directory)
	BEP44      bool   // Deprecated: BEP-44 removed; retained for JSON compat
	// TTLHours overrides the config default (IdentityRecordTTL) for this publish.
	// 0 = use config default (typically 48h). -1 = no expiry.
	TTLHours int
}

// IdentityPublish broadcasts an identity to configured decentralized registries.
func (m *IdentityManager) IdentityPublish(ctx context.Context, handle string, opts IdentityPublishOptions) error {
	if !strings.HasPrefix(handle, "@") {
		return fmt.Errorf("handle must start with @")
	}

	name := "default"
	if opts.Name != "" {
		name = opts.Name
	}

	// 1. Load the identity (including private keys for signing the record).
	id, err := m.LoadIdentity(name, []byte(opts.Passphrase), "", false)
	if err != nil {
		return err
	}
	defer id.Wipe()

	// 2. Create and sign the record.
	var expiresAt time.Time
	switch {
	case opts.TTLHours < 0:
		// No expiry — zero value means never expires (legacy compat).
	case opts.TTLHours > 0:
		expiresAt = time.Now().Add(time.Duration(opts.TTLHours) * time.Hour)
	default:
		expiresAt = time.Now().Add(m.Config.IdentityTTL())
	}
	record := &IdentityRecord{
		Handle:    handle,
		KEMPubKey: id.KEMPub,
		SIGPubKey: id.SIGPub,
		Timestamp: time.Now(),
		ExpiresAt: expiresAt,
	}
	if err := record.Sign(id.SIGPriv); err != nil {
		return fmt.Errorf("failed to sign identity record: %w", err)
	}

	// 3. Dispatch to selected registries.
	published := false

	if opts.Local {
		if m.Contacts == nil {
			return fmt.Errorf("contact manager not initialized")
		}
		if err := m.Contacts.Add(&Contact{
			Petname:   handle,
			KEMPubKey: record.KEMPubKey,
			SIGPubKey: record.SIGPubKey,
			AddedAt:   time.Now(),
		}); err != nil {
			return err
		}
		published = true
	}

	if opts.Desec {
		token := opts.DesecToken
		if token == "" {
			token = os.Getenv("DESEC_TOKEN")
		}
		if token == "" {
			return fmt.Errorf("deSEC token required (--desec-token or DESEC_TOKEN env)")
		}
		dnsReg := NewDNSRegistry(m.Config)
		if err := dnsReg.PublishWithKey(ctx, record, []byte(token)); err != nil {
			return err
		}
		published = true
	}

	if opts.WKD {
		wkdReg := NewWKDRegistry(m.Config)
		err := wkdReg.Publish(ctx, record)
		var wkdManual *ErrWKDPublishManual
		if errors.As(err, &wkdManual) {
			// Surface as a structured publish result — not an error.
			return wkdManual
		}
		if err != nil {
			return fmt.Errorf("WKD publish failed: %w", err)
		}
		published = true
	}

	if !published {
		return fmt.Errorf("no registry selected — use --wkd, --dns, --desec, or --local")
	}

	return nil
}
