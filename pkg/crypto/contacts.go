package crypto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

// Contact represents a locally trusted identity (Petname).
type Contact struct {
	Petname   string    `json:"petname"`  // Local alias (e.g., "@alice")
	KEMPubKey []byte    `json:"kem_pub"`  // ML-KEM Public Key
	SIGPubKey []byte    `json:"sig_pub"`  // ML-DSA Public Key
	Nickname  string    `json:"nickname"` // Peer's suggested name
	AddedAt   time.Time `json:"added_at"`
	Notes     string    `json:"notes,omitempty"`
}

// ContactManager handles the local address book of trusted peers.
type ContactManager struct {
	db   *bbolt.DB
	path string
}

const contactBucket = "contacts"

func NewContactManager() (*ContactManager, error) {
	home := GetUserHomeDir()
	path := filepath.Join(home, MaknoonDir, "contacts.db")

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open contacts database: %w", err)
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(contactBucket))
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	return &ContactManager{db: db, path: path}, nil
}

func (m *ContactManager) Close() error {
	return m.db.Close()
}

// Add saves a new contact or updates an existing one.
func (m *ContactManager) Add(c *Contact) error {
	if !strings.HasPrefix(c.Petname, "@") {
		return fmt.Errorf("petname must start with @")
	}

	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(contactBucket))
		data, _ := json.Marshal(c)
		return b.Put([]byte(strings.ToLower(c.Petname)), data)
	})
}

// Get retrieves a contact by their petname.
func (m *ContactManager) Get(petname string) (*Contact, error) {
	var c Contact
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(contactBucket))
		v := b.Get([]byte(strings.ToLower(petname)))
		if v == nil {
			return fmt.Errorf("contact '%s' not found", petname)
		}
		return json.Unmarshal(v, &c)
	})
	return &c, err
}

// List returns all saved contacts.
func (m *ContactManager) List() ([]*Contact, error) {
	var contacts []*Contact
	err := m.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(contactBucket))
		return b.ForEach(func(_, v []byte) error {
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
	return m.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(contactBucket))
		return b.Delete([]byte(strings.ToLower(petname)))
	})
}
