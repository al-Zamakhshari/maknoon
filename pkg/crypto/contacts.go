package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Contact represents a locally trusted identity (Petname).
type Contact struct {
	Petname   string    `json:"petname"`  // Local alias (e.g., "@alice")
	KEMPubKey []byte    `json:"kem_pub"`  // ML-KEM Public Key
	SIGPubKey []byte    `json:"sig_pub"`  // ML-DSA Public Key
	PeerID    string    `json:"peer_id"`  // Key fingerprint (mk<16hex>)
	Nickname  string    `json:"nickname"` // Peer's suggested name
	AddedAt   time.Time `json:"added_at"`
	Notes     string    `json:"notes,omitempty"`
}

// DerivePeerID returns a stable key fingerprint for a Maknoon signing public key.
// Format: "mk" + first 8 bytes of SHA-256(sigPub) as hex = 18 characters.
func DerivePeerID(sigPub []byte) (string, error) {
	if len(sigPub) == 0 {
		return "", fmt.Errorf("signing public key required for fingerprint derivation")
	}
	h := sha256.Sum256(sigPub)
	return "mk" + hex.EncodeToString(h[:8]), nil
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
