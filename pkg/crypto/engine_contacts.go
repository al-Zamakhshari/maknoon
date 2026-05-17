package crypto

import (
	"encoding/hex"
	"fmt"
)

// --- Engine Wrappers ---

func (e *Engine) ContactAdd(ectx *EngineContext, petname, kemPub, sigPub, note string) error {
	return e.Identity.ContactAdd(ectx, petname, kemPub, sigPub, note)
}

func (e *Engine) ContactList(ectx *EngineContext) ([]*Contact, error) {
	return e.Identity.ContactList(ectx)
}

func (e *Engine) ContactDelete(ectx *EngineContext, petname string) error {
	return e.Identity.ContactDelete(ectx, petname)
}

// --- IdentityService Implementation ---

func (s *IdentityService) ContactAdd(ectx *EngineContext, petname, kemPub, sigPub, note string) error {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapIdentity); err != nil {
		return err
	}

	if err := s.engine.ensureContacts(); err != nil {
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

	return s.engine.Contacts.Add(contact)
}

func (s *IdentityService) ContactList(ectx *EngineContext) ([]*Contact, error) {
	if err := s.engine.ensureContacts(); err != nil {
		return nil, err
	}
	return s.engine.Contacts.List()
}

func (s *IdentityService) ContactDelete(ectx *EngineContext, petname string) error {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapIdentity); err != nil {
		return err
	}
	if err := s.engine.ensureContacts(); err != nil {
		return err
	}
	return s.engine.Contacts.Delete(petname)
}

func (e *Engine) ensureContacts() error {
	e.contactsMu.Lock()
	defer e.contactsMu.Unlock()

	if e.Contacts != nil {
		return nil
	}

	store, err := e.Vault.Store.Open(e.contactsPath)
	if err != nil {
		return fmt.Errorf("failed to open contacts store: %w", err)
	}

	e.Contacts = NewContactManager(store)
	if e.Identity.Mgr != nil {
		e.Identity.Mgr.Contacts = e.Contacts
	}

	return nil
}
