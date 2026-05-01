package crypto

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// IdentityPublishOptions settings for publishing an identity.
type IdentityPublishOptions struct {
	Name       string // Local identity name
	Passphrase string // Passphrase to unlock local identity
	Local      bool   // Add to local contacts
	DNS        bool   // Publish to DNS (via DHT)
	Desec      bool   // Publish to deSEC
	DesecToken string // deSEC API token
	Nostr      bool   // Publish to Nostr
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

	// 1. Load the identity (including private keys for signing the record)
	id, err := m.LoadIdentity(name, []byte(opts.Passphrase), "", false)
	if err != nil {
		return err
	}
	defer id.Wipe()

	// 2. Create and sign record
	record := &IdentityRecord{
		Handle:    handle,
		KEMPubKey: id.KEMPub,
		SIGPubKey: id.SIGPub,
		Timestamp: time.Now(),
	}

	if err := record.Sign(id.SIGPriv); err != nil {
		return fmt.Errorf("failed to sign identity record: %w", err)
	}

	// 3. Dispatch to registries
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
	}

	if opts.Desec {
		token := opts.DesecToken
		if token == "" {
			token = os.Getenv("DESEC_TOKEN")
		}
		if token == "" {
			return fmt.Errorf("deSEC token required")
		}

		dnsReg := NewDNSRegistry()
		if err := dnsReg.PublishWithKey(ctx, record, []byte(token)); err != nil {
			return err
		}
	}

	// Default to Nostr
	if opts.Nostr || (!opts.DNS && !opts.Desec) {
		nostrReg := NewNostrRegistry()
		if len(id.NostrPriv) == 0 {
			return fmt.Errorf("nostr private key not found")
		}
		if err := nostrReg.PublishWithKey(ctx, record, id.NostrPriv); err != nil {
			return err
		}
	}

	return nil
}
