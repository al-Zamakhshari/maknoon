package crypto

import (
	"encoding/binary"
	"fmt"
)

// SplitIdentity breaks an identity into mnemonic shards using Shamir's Secret Sharing.
func (m *IdentityManager) SplitIdentity(name string, threshold, shares int, passphrase string) ([]string, error) {
	// 1. Load the identity
	id, err := m.LoadIdentity(name, []byte(passphrase), "", false)
	if err != nil {
		return nil, err
	}
	defer id.Wipe()

	// 2. Pack the keys
	blob := make([]byte, 12+len(id.KEMPriv)+len(id.SIGPriv)+len(id.NostrPriv))
	offset := 0
	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(len(id.KEMPriv)))
	copy(blob[offset+4:offset+4+len(id.KEMPriv)], id.KEMPriv)
	offset += 4 + len(id.KEMPriv)

	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(len(id.SIGPriv)))
	copy(blob[offset+4:offset+4+len(id.SIGPriv)], id.SIGPriv)
	offset += 4 + len(id.SIGPriv)

	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(len(id.NostrPriv)))
	copy(blob[offset+4:], id.NostrPriv)

	defer SafeClear(blob)

	// 3. Split
	shards, err := SplitSecret(blob, threshold, shares)
	if err != nil {
		return nil, err
	}

	var results []string
	for _, s := range shards {
		results = append(results, s.ToMnemonic())
	}
	return results, nil
}

// CombineIdentity reconstructs an identity from mnemonic shards.
func (m *IdentityManager) CombineIdentity(mnemonics []string, output, passphrase string, noPassword bool) (string, error) {
	var shards []Share
	for _, mn := range mnemonics {
		s, err := FromMnemonic(mn)
		if err != nil {
			return "", err
		}
		shards = append(shards, *s)
	}

	combined, err := CombineShares(shards)
	if err != nil {
		return "", err
	}
	defer SafeClear(combined)

	// Unpack
	offset := 0
	if len(combined) < 4 {
		return "", fmt.Errorf("combined secret too short")
	}
	kemLen := binary.BigEndian.Uint32(combined[offset : offset+4])
	if len(combined) < offset+4+int(kemLen)+4 {
		return "", fmt.Errorf("combined secret corrupted (KEM length mismatch)")
	}
	kemPriv := combined[offset+4 : offset+4+int(kemLen)]
	offset += 4 + int(kemLen)

	sigLen := binary.BigEndian.Uint32(combined[offset : offset+4])
	if len(combined) < offset+4+int(sigLen) {
		return "", fmt.Errorf("combined secret corrupted (SIG length mismatch)")
	}
	sigPriv := combined[offset+4 : offset+4+int(sigLen)]
	offset += 4 + int(sigLen)

	nostrPriv := combined[offset+4:]

	// Store
	basePath, baseName, err := m.ResolveBaseKeyPath(output)
	if err != nil {
		return "", err
	}

	// Reconstruct public keys to save full identity
	kemPub, err := DeriveKEMPublic(kemPriv)
	if err != nil {
		return "", err
	}
	sigPub, err := DeriveSIGPublic(sigPriv)
	if err != nil {
		return "", err
	}
	var nostrPub []byte
	if len(nostrPriv) > 0 {
		nostrPub, _ = DeriveNostrPublic(nostrPriv)
	}

	pass := []byte(passphrase)
	if noPassword {
		pass = nil
	}

	// Use existing SaveIdentity logic for consistency
	if err := m.SaveIdentity(basePath, baseName, kemPub, kemPriv, sigPub, sigPriv, nostrPub, nostrPriv, pass, 1); err != nil {
		return "", err
	}

	return basePath, nil
}
