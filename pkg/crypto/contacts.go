package crypto

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// Contact represents a locally trusted identity (Petname).
type Contact struct {
	Petname   string    `json:"petname"`  // Local alias (e.g., "@alice")
	KEMPubKey []byte    `json:"kem_pub"`  // ML-KEM Public Key
	SIGPubKey []byte    `json:"sig_pub"`  // ML-DSA Public Key
	PeerID    string    `json:"peer_id"`  // libp2p Peer ID for NAT traversal
	Nickname  string    `json:"nickname"` // Peer's suggested name
	AddedAt   time.Time `json:"added_at"`
	Notes     string    `json:"notes,omitempty"`
}

// DerivePeerID derives a libp2p PeerID from a Maknoon signing public key.
// It supports Hybrid SIG (ML-DSA + Ed25519) and fallback derivation.
func DerivePeerID(sigPub []byte) (string, error) {
	if len(sigPub) == 0 {
		return "", fmt.Errorf("signing public key required for peer ID derivation")
	}

	var edPubBytes []byte

	// 1. Check for Hybrid Format (ML-DSA-87 + Ed25519)
	// ML-DSA-87 Pub is 2592 bytes, Ed25519 Pub is 32 bytes.
	if len(sigPub) >= 2592+32 {
		edPubBytes = sigPub[2592 : 2592+32]
	} else if len(sigPub) >= 1952+32 { // ML-DSA-65
		edPubBytes = sigPub[1952 : 1952+32]
	} else if len(sigPub) >= 64+32 { // SLH-DSA
		edPubBytes = sigPub[len(sigPub)-32:]
	} else {
		// 2. Fallback: Deterministic derivation from the first 32 bytes
		// This must match the fallback in Identity.AsLibp2pKey
		seed := sigPub
		if len(seed) > 32 {
			seed = seed[:32]
		}
		// In fallback, we treat sigPub[:32] as the public key directly if it's 32 bytes
		// But that's risky. However, for consistency with old identities:
		if len(seed) == 32 {
			edPubBytes = seed
		} else {
			return "", fmt.Errorf("unsupported public key size for PeerID derivation")
		}
	}

	pub, err := libp2pcrypto.UnmarshalEd25519PublicKey(edPubBytes)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return "", err
	}

	return id.String(), nil
}

// ContactManager handles the local address book of trusted peers.
type ContactManager struct {
	store Store
}

const contactBucket = "contacts"

func NewContactManager(s Store) *ContactManager {
	return &ContactManager{store: s}
}

func (m *ContactManager) Close() error {
	return m.store.Close()
}

// Add saves a new contact or updates an existing one.
func (m *ContactManager) Add(c *Contact) error {
	if !strings.HasPrefix(c.Petname, "@") {
		return fmt.Errorf("petname must start with @")
	}

	return m.store.Update(func(tx Transaction) error {
		data, _ := json.Marshal(c)
		return tx.Put(contactBucket, strings.ToLower(c.Petname), data)
	})
}

// Get retrieves a contact by their petname.
func (m *ContactManager) Get(petname string) (*Contact, error) {
	var c Contact
	err := m.store.View(func(tx Transaction) error {
		v := tx.Get(contactBucket, strings.ToLower(petname))
		if v == nil {
			return fmt.Errorf("contact '%s' not found", petname)
		}
		return json.Unmarshal(v, &c)
	})
	return &c, err
}

// GetByPeerID retrieves a contact by their libp2p Peer ID.
func (m *ContactManager) GetByPeerID(peerID string) (*Contact, error) {
	var c *Contact
	err := m.store.View(func(tx Transaction) error {
		return tx.ForEach(contactBucket, func(_, v []byte) error {
			var curr Contact
			if err := json.Unmarshal(v, &curr); err == nil {
				if curr.PeerID == peerID {
					c = &curr
					return io.EOF // Found, stop iteration
				}
			}
			return nil
		})
	})
	if err == io.EOF {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("contact with PeerID '%s' not found", peerID)
}

// List returns all saved contacts.
func (m *ContactManager) List() ([]*Contact, error) {
	var contacts []*Contact
	err := m.store.View(func(tx Transaction) error {
		return tx.ForEach(contactBucket, func(_, v []byte) error {
			var c Contact
			if err := json.Unmarshal(v, &c); err == nil {
				contacts = append(contacts, &c)
			}
			return nil
		})
	})
	return contacts, err
}

// Delete removes a contact from the address book.
func (m *ContactManager) Delete(petname string) error {
	return m.store.Update(func(tx Transaction) error {
		return tx.Delete(contactBucket, strings.ToLower(petname))
	})
}
