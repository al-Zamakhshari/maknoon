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
	Name       string   // Local identity name
	Passphrase string   // Passphrase to unlock local identity
	Local      bool     // Add to local contacts
	LibP2P     bool     // Deprecated: libp2p-kad-dht was removed; this field is ignored
	Nostr      bool     // Publish to Nostr relays
	DNS        bool     // Publish to DNS (via DHT)
	Desec      bool     // Publish to deSEC
	DesecToken string   // deSEC API token
	BEP44      bool     // Publish mini-record to BitTorrent BEP-44 DHT (opt-in peer discovery)
	Multiaddrs []string // Optional Multiaddrs to broadcast
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
		Handle:     handle,
		KEMPubKey:  id.KEMPub,
		SIGPubKey:  id.SIGPub,
		Timestamp:  time.Now(),
		ExpiresAt:  time.Now().Add(m.Config.IdentityTTL()),
		Multiaddrs: opts.Multiaddrs,
	}

	// 2b. Attempt to capture active P2P Multiaddrs if none provided
	if len(record.Multiaddrs) == 0 && m.P2P != nil {
		if sess, err := m.P2P.ChatStart(nil, name, ""); err == nil {
			// Wait a bit for libp2p to detect addresses
			time.Sleep(2 * time.Second)
			record.Multiaddrs = sess.Multiaddrs()
			sess.Close()
		}
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

		dnsReg := NewDNSRegistry(m.Config)
		if err := dnsReg.PublishWithKey(ctx, record, []byte(token)); err != nil {
			return err
		}
	}

	// Default to Nostr when no specific registry is selected.
	// libp2p-kad-dht was removed (GO-2024-3218); Nostr is now the primary registry.
	if opts.Nostr || (!opts.DNS && !opts.Desec && !opts.BEP44 && !opts.Local) {
		nostrPriv, err := DeriveNostrKeypair(id.SIGPriv)
		if err != nil {
			return fmt.Errorf("nostr key derivation failed: %w", err)
		}
		nostrReg := NewNostrRegistry(m.Config)
		if err := nostrReg.PublishWithKey(ctx, record, nostrPriv); err != nil {
			return fmt.Errorf("nostr publish failed: %w", err)
		}
	}

	if opts.BEP44 {
		bep44Reg := NewBEP44Registry(m.Config)
		if err := bep44Reg.PublishWithSIGKey(ctx, record, id.SIGPriv); err != nil {
			return fmt.Errorf("bep44 publish failed: %w", err)
		}
	}

	return nil
}
