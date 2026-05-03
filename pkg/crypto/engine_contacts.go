package crypto

import (
	"encoding/hex"
	"fmt"
)

func (e *Engine) ensureContacts() error {
	e.contactsMu.Lock()
	defer e.contactsMu.Unlock()

	if e.Contacts != nil {
		return nil
	}

	store, err := e.Vaults.Open(e.contactsPath)
	if err != nil {
		return fmt.Errorf("failed to open contacts store: %w", err)
	}

	e.Contacts = NewContactManager(store)
	if e.Identities != nil {
		e.Identities.Contacts = e.Contacts
	}

	return nil
}

func (e *Engine) ContactAdd(ectx *EngineContext, petname, kemPub, sigPub, note string) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return err
	}

	if err := e.ensureContacts(); err != nil {
		return err
	}

	kemBytes, err := hex.DecodeString(kemPub)
	if err != nil {
		return fmt.Errorf("invalid KEM public key: %w", err)
	}
	sigBytes, err := hex.DecodeString(sigPub)
	if err != nil {
		return fmt.Errorf("invalid SIG public key: %w", err)
	}

	peerID, err := DerivePeerID(sigBytes)
	if err != nil {
		return err
	}

	contact := &Contact{
		Petname:   petname,
		KEMPubKey: kemBytes,
		SIGPubKey: sigBytes,
		PeerID:    peerID,
		Notes:     note,
	}

	return e.Contacts.Add(contact)
}

func (e *Engine) ContactList(ectx *EngineContext) ([]*Contact, error) {
	if err := e.ensureContacts(); err != nil {
		return nil, err
	}
	return e.Contacts.List()
}

func (e *Engine) ContactDelete(ectx *EngineContext, petname string) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return err
	}
	if err := e.ensureContacts(); err != nil {
		return err
	}
	return e.Contacts.Delete(petname)
}
