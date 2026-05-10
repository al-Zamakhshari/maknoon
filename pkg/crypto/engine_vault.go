package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// VaultInitInstitutional creates a new institutional vault governed by a quorum.
func (e *Engine) VaultInitInstitutional(ectx *EngineContext, name string, threshold, shares int, peerIDs []string, passphrase []byte) (*VaultResult, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultWrite); err != nil {
		return nil, err
	}

	path, err := e.resolveVaultPath(name)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); err == nil {
		return nil, &ErrState{Reason: fmt.Sprintf("vault '%s' already exists", name)}
	}

	// 1. Shard the master passphrase using SSS
	mnemonics, err := e.VaultSplit(ectx, path, threshold, shares, string(passphrase))
	if err != nil {
		return nil, fmt.Errorf("failed to shard passphrase: %w", err)
	}

	// 2. Open vault and save metadata
	store, err := e.Vaults.Open(path)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	err = store.Update(func(tx Transaction) error {
		// Save Salt
		salt := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return err
		}
		if err := tx.Put(metaBucket, saltKey, salt); err != nil {
			return err
		}

		// Save Institutional Marker
		if err := tx.Put(metaBucket, institutionalKey, []byte("true")); err != nil {
			return err
		}

		// Save Quorum Peers
		peersJSON, _ := json.Marshal(peerIDs)
		if err := tx.Put(metaBucket, quorumPeersKey, peersJSON); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &VaultResult{
		Status:          "success",
		Message:         fmt.Sprintf("Institutional vault '%s' initialized. Distribute the %d shares to the authorized peers.", name, shares),
		IsInstitutional: true,
		Threshold:       threshold,
		Shares:          mnemonics,
		QuorumPeers:     peerIDs,
	}, nil
}

// VaultStatus returns the governance status of a vault.
func (e *Engine) VaultStatus(ectx *EngineContext, name string) (*VaultResult, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultRead); err != nil {
		return nil, err
	}
	path, err := e.resolveVaultPath(name)
	if err != nil {
		return nil, err
	}

	store, err := e.Vaults.Open(path)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	var res VaultResult
	err = store.View(func(tx Transaction) error {
		inst := tx.Get(metaBucket, institutionalKey)
		res.IsInstitutional = string(inst) == "true"

		peersRaw := tx.Get(metaBucket, quorumPeersKey)
		if peersRaw != nil {
			json.Unmarshal(peersRaw, &res.QuorumPeers)
		}
		return nil
	})

	res.Status = "success"
	res.Vault = name
	return &res, err
}

// VaultSet encrypts and saves a vault entry to disk.
func (e *Engine) VaultSet(ectx *EngineContext, vaultPath string, entry *VaultEntry, passphrase []byte, pin string, overwrite bool) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultWrite); err != nil {
		return err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := e.resolveVaultPath(vaultPath)
	if err != nil {
		return err
	}

	if err := ectx.Policy.ValidatePath(path); err != nil {
		return err
	}

	store, err := e.Vaults.Open(path)
	if err != nil {
		return err
	}
	defer store.Close()

	return store.Update(func(tx Transaction) error {
		// Get or create salt
		salt := tx.Get(metaBucket, saltKey)
		if salt == nil {
			salt = make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, salt); err != nil {
				return err
			}
			if err := tx.Put(metaBucket, saltKey, salt); err != nil {
				return err
			}
		}

		key := DeriveVaultKey(passphrase, salt)
		defer SafeClear(key)

		payload, err := SealEntry(entry, key)
		if err != nil {
			return err
		}

		// Use Hashed key for privacy
		serviceKey := Sha256Hex([]byte(strings.ToLower(entry.Service)))
		if !overwrite {
			if tx.Get(vaultBucket, serviceKey) != nil {
				return &ErrState{Reason: fmt.Sprintf("service '%s' already exists (use overwrite to replace)", entry.Service)}
			}
		}

		return tx.Put(vaultBucket, serviceKey, payload)
	})
}

// VaultGet reads and decrypts a vault entry from disk.
func (e *Engine) VaultGet(ectx *EngineContext, vaultPath string, service string, passphrase []byte, pin string) (*VaultEntry, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultRead); err != nil {
		return nil, err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := e.resolveVaultPath(vaultPath)
	if err != nil {
		return nil, err
	}

	if err := ectx.Policy.ValidatePath(path); err != nil {
		return nil, err
	}

	store, err := e.Vaults.Open(path)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	// 1. Check Governance Status
	var isInstitutional bool
	var quorumPeers []string
	store.View(func(tx Transaction) error {
		inst := tx.Get(metaBucket, institutionalKey)
		isInstitutional = string(inst) == "true"
		peersRaw := tx.Get(metaBucket, quorumPeersKey)
		if peersRaw != nil {
			json.Unmarshal(peersRaw, &quorumPeers)
		}
		return nil
	})

	// 2. Handle Quorum Unlocking if necessary
	finalPassphrase := passphrase
	if isInstitutional && len(passphrase) == 0 {
		e.Logger.Info("Institutional vault detected: initiating quorum unlock", "vault", vaultPath, "peers", len(quorumPeers))
		responses, err := e.QuorumRequest(ectx, "", quorumPeers, ActionVaultUnlock, vaultPath, "Consensus-based vault access requested")
		if err != nil {
			return nil, fmt.Errorf("quorum request failed: %w", err)
		}

		var shares []string
		for _, r := range responses {
			if r.Approved && len(r.Payload) > 0 {
				shares = append(shares, string(r.Payload))
			}
		}

		if len(shares) == 0 {
			return nil, &ErrAuthentication{Reason: "quorum failed: no approvals received from authorized peers"}
		}

		// Attempt recovery from collected shares
		recovered, err := e.VaultRecover(ectx, shares, vaultPath, "", "")
		if err != nil {
			return nil, fmt.Errorf("quorum recovery failed: %w (threshold may not have been met)", err)
		}
		finalPassphrase = []byte(recovered)
		defer SafeClear(finalPassphrase)
	}

	var entry *VaultEntry
	err = store.View(func(tx Transaction) error {
		salt := tx.Get(metaBucket, saltKey)
		if salt == nil {
			return &ErrAuthentication{Reason: "vault salt missing"}
		}

		// Use Hashed key
		serviceKey := Sha256Hex([]byte(strings.ToLower(service)))
		payload := tx.Get(vaultBucket, serviceKey)
		if payload == nil {
			return &ErrState{Reason: fmt.Sprintf("service '%s' not found", service)}
		}

		key := DeriveVaultKey(finalPassphrase, salt)
		defer SafeClear(key)

		var err error
		entry, err = OpenEntry(payload, key)
		return err
	})

	return entry, err
}

func (e *Engine) VaultDelete(ectx *EngineContext, name string) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultDelete); err != nil {
		return err
	}
	path, err := e.resolveVaultPath(name)
	if err != nil {
		return err
	}
	if err := ectx.Policy.ValidatePath(path); err != nil {
		return err
	}

	return e.Vaults.DeleteVault(path)
}

func (e *Engine) VaultRename(ectx *EngineContext, oldName, newName string) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultWrite); err != nil {
		return err
	}
	oldPath, err := e.resolveVaultPath(oldName)
	if err != nil {
		return err
	}
	newPath, err := e.resolveVaultPath(newName)
	if err != nil {
		return err
	}

	if err := ectx.Policy.ValidatePath(oldPath); err != nil {
		return err
	}
	if err := ectx.Policy.ValidatePath(newPath); err != nil {
		return err
	}

	if _, err := os.Stat(oldPath); err != nil {
		return &ErrState{Reason: fmt.Sprintf("vault '%s' not found", oldName)}
	}
	if _, err := os.Stat(newPath); err == nil {
		return &ErrState{Reason: fmt.Sprintf("target vault '%s' already exists", newName)}
	}

	return os.Rename(oldPath, newPath)
}

func (e *Engine) VaultList(ectx *EngineContext, vaultPath string, passphrase []byte) ([]VaultListEntry, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultRead); err != nil {
		return nil, err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := e.resolveVaultPath(vaultPath)
	if err != nil {
		return nil, err
	}
	if err := ectx.Policy.ValidatePath(path); err != nil {
		return nil, err
	}

	store, err := e.Vaults.Open(path)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	// 1. Check Governance Status
	var isInstitutional bool
	var quorumPeers []string
	store.View(func(tx Transaction) error {
		inst := tx.Get(metaBucket, institutionalKey)
		isInstitutional = string(inst) == "true"
		peersRaw := tx.Get(metaBucket, quorumPeersKey)
		if peersRaw != nil {
			json.Unmarshal(peersRaw, &quorumPeers)
		}
		return nil
	})

	// 2. Handle Quorum Unlocking if necessary
	finalPassphrase := passphrase
	if isInstitutional && len(passphrase) == 0 {
		e.Logger.Info("Institutional vault detected: initiating quorum unlock for listing", "vault", vaultPath)
		responses, err := e.QuorumRequest(ectx, "", quorumPeers, ActionVaultUnlock, vaultPath, "Consensus-based vault listing requested")
		if err != nil {
			return nil, fmt.Errorf("quorum request failed: %w", err)
		}

		var shares []string
		for _, r := range responses {
			if r.Approved && len(r.Payload) > 0 {
				shares = append(shares, string(r.Payload))
			}
		}

		if len(shares) == 0 {
			return nil, &ErrAuthentication{Reason: "quorum failed: no approvals received from authorized peers"}
		}

		recovered, err := e.VaultRecover(ectx, shares, vaultPath, "", "")
		if err != nil {
			return nil, fmt.Errorf("quorum recovery failed: %w (threshold may not have been met)", err)
		}
		finalPassphrase = []byte(recovered)
		defer SafeClear(finalPassphrase)
	}

	var entries []VaultListEntry
	err = store.View(func(tx Transaction) error {
		salt := tx.Get(metaBucket, saltKey)
		if salt == nil {
			return &ErrAuthentication{Reason: "vault salt missing"}
		}

		key := DeriveVaultKey(finalPassphrase, salt)
		defer SafeClear(key)

		return tx.ForEach(vaultBucket, func(_, v []byte) error {
			entry, err := OpenEntry(v, key)
			if err == nil {
				entries = append(entries, VaultListEntry{
					Service:  entry.Service,
					Username: entry.Username,
				})
			}
			return nil
		})
	})
	return entries, err
}

func (e *Engine) VaultSplit(ectx *EngineContext, vaultPath string, threshold, shares int, passphrase string) ([]string, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultRead); err != nil {
		return nil, err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := e.resolveVaultPath(vaultPath)
	if err != nil {
		return nil, err
	}
	return SplitVault(path, threshold, shares, passphrase)
}

func (e *Engine) VaultRecover(ectx *EngineContext, mnemonics []string, vaultPath string, output string, passphrase string) (string, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultWrite); err != nil {
		return "", err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := e.resolveVaultPath(vaultPath)
	if err != nil {
		return "", err
	}

	// 1. Recover the master passphrase from shards
	recoveredPass, err := RecoverVault(mnemonics, path, output, passphrase)
	if err != nil {
		return "", err
	}

	// 2. If output is specified, migrate entries to the new vault
	if output != "" {
		// List entries from source vault
		entries, err := e.VaultList(ectx, path, []byte(recoveredPass))
		if err != nil {
			return "", fmt.Errorf("failed to list entries from source vault: %w", err)
		}

		// Create/Open target vault
		outputPath, err := e.resolveVaultPath(output)
		if err != nil {
			return "", err
		}

		for _, entry := range entries {
			// Get full entry (with password)
			fullEntry, err := e.VaultGet(ectx, path, entry.Service, []byte(recoveredPass), "")
			if err != nil {
				return "", fmt.Errorf("failed to get entry '%s': %w", entry.Service, err)
			}

			// Set in new vault
			err = e.VaultSet(ectx, outputPath, fullEntry, []byte(recoveredPass), "", true)
			if err != nil {
				return "", fmt.Errorf("failed to set entry '%s' in recovered vault: %w", entry.Service, err)
			}
		}
	}

	return recoveredPass, nil
}

func (e *Engine) VaultCheckShards(ectx *EngineContext, mnemonics []string) (*VaultResult, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultRead); err != nil {
		return nil, err
	}

	if len(mnemonics) == 0 {
		return nil, &ErrFormat{Reason: "no shards provided"}
	}

	var threshold int
	for i, m := range mnemonics {
		s, err := FromMnemonic(m)
		if err != nil {
			return nil, fmt.Errorf("shard %d is invalid: %w", i+1, err)
		}
		if i == 0 {
			threshold = int(s.Threshold)
		} else if int(s.Threshold) != threshold {
			return nil, fmt.Errorf("shard %d has inconsistent threshold (expected %d, got %d)", i+1, threshold, s.Threshold)
		}

		// Verify checksum
		h := hmac.New(sha256.New, shardChecksumKey)
		h.Write([]byte{s.Version, s.Threshold, s.Index})
		h.Write(s.Data)
		sum := h.Sum(nil)
		if !hmac.Equal(s.Checksum, sum[:ChecksumSize]) {
			return nil, fmt.Errorf("checksum mismatch for shard %d", i+1)
		}
	}

	msg := fmt.Sprintf("Validated %d healthy shards. Recovery requires %d shards.", len(mnemonics), threshold)
	if len(mnemonics) < threshold {
		msg += fmt.Sprintf(" You still need %d more shard(s) to recover.", threshold-len(mnemonics))
	}

	return &VaultResult{
		Status:    "success",
		Message:   msg,
		Threshold: threshold,
	}, nil
}

func (e *Engine) VaultRotate(ectx *EngineContext, vaultPath string, oldPassphrase, newPassphrase []byte) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapVaultWrite); err != nil {
		return err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := e.resolveVaultPath(vaultPath)
	if err != nil {
		return err
	}

	if err := ectx.Policy.ValidatePath(path); err != nil {
		return err
	}

	store, err := e.Vaults.Open(path)
	if err != nil {
		return err
	}
	defer store.Close()

	// 1. Read and decrypt all entries in memory
	var entries []*VaultEntry
	err = store.View(func(tx Transaction) error {
		salt := tx.Get(metaBucket, saltKey)
		if salt == nil {
			return &ErrAuthentication{Reason: "vault salt missing"}
		}

		oldKey := DeriveVaultKey(oldPassphrase, salt)
		defer SafeClear(oldKey)

		return tx.ForEach(vaultBucket, func(k, v []byte) error {
			entry, err := OpenEntry(v, oldKey)
			if err != nil {
				return err
			}
			entries = append(entries, entry)
			return nil
		})
	})
	if err != nil {
		return err
	}

	// 2. Perform in-place rotation with fresh salt and new key
	return store.Update(func(tx Transaction) error {
		// Generate fresh salt
		newSalt := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
			return err
		}

		newKey := DeriveVaultKey(newPassphrase, newSalt)
		defer SafeClear(newKey)

		// Update salt in metadata
		if err := tx.Put(metaBucket, saltKey, newSalt); err != nil {
			return err
		}

		// Re-encrypt and update all entries
		for _, entry := range entries {
			payload, err := SealEntry(entry, newKey)
			if err != nil {
				return err
			}
			// Service key remains the same (Hashed service name)
			serviceKey := Sha256Hex([]byte(strings.ToLower(entry.Service)))
			if err := tx.Put(vaultBucket, serviceKey, payload); err != nil {
				return err
			}
		}

		return nil
	})
}

func (e *Engine) resolveVaultPath(name string) (string, error) {
	if name == "" {
		return "", &ErrFormat{Reason: "vault name required"}
	}
	if filepath.IsAbs(name) || strings.Contains(name, string(os.PathSeparator)) {
		return name, nil
	}
	return filepath.Join(e.Config.Paths.VaultsDir, name+".vault"), nil
}
