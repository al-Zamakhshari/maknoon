package crypto

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// --- Engine Wrappers ---

func (e *Engine) VaultInitInstitutional(ectx *EngineContext, name string, threshold, shares int, peerIDs []string, passphrase []byte) (*VaultResult, error) {
	return e.Vault.InitInstitutional(ectx, name, threshold, shares, peerIDs, passphrase)
}

func (e *Engine) VaultStatus(ectx *EngineContext, name string) (*VaultResult, error) {
	return e.Vault.Status(ectx, name)
}

func (e *Engine) VaultSet(ectx *EngineContext, vaultPath string, entry *VaultEntry, passphrase []byte, pin string, overwrite bool) error {
	return e.Vault.Set(ectx, vaultPath, entry, passphrase, pin, overwrite)
}

func (e *Engine) VaultGet(ectx *EngineContext, vaultPath string, service string, passphrase []byte, pin string) (*VaultEntry, error) {
	return e.Vault.Get(ectx, vaultPath, service, passphrase, pin)
}

func (e *Engine) VaultDelete(ectx *EngineContext, name string) error {
	return e.Vault.Delete(ectx, name)
}

func (e *Engine) VaultRename(ectx *EngineContext, oldName, newName string) error {
	return e.Vault.Rename(ectx, oldName, newName)
}

func (e *Engine) VaultList(ectx *EngineContext, vaultPath string, passphrase []byte) ([]VaultListEntry, error) {
	return e.Vault.List(ectx, vaultPath, passphrase)
}

func (e *Engine) VaultSplit(ectx *EngineContext, vaultPath string, threshold, shares int, passphrase string) ([]string, error) {
	return e.Vault.Split(ectx, vaultPath, threshold, shares, passphrase)
}

func (e *Engine) VaultRecover(ectx *EngineContext, mnemonics []string, vaultPath string, output string, passphrase string) (string, error) {
	return e.Vault.Recover(ectx, mnemonics, vaultPath, output, passphrase)
}

func (e *Engine) VaultCheckShards(ectx *EngineContext, mnemonics []string) (*VaultResult, error) {
	return e.Vault.CheckShards(ectx, mnemonics)
}

func (e *Engine) VaultRotate(ectx *EngineContext, vaultPath string, oldPassphrase, newPassphrase []byte) error {
	return e.Vault.Rotate(ectx, vaultPath, oldPassphrase, newPassphrase)
}

// --- VaultService Implementation ---

func (s *VaultService) InitInstitutional(ectx *EngineContext, name string, threshold, shares int, peerIDs []string, passphrase []byte) (*VaultResult, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapVaultWrite); err != nil {
		return nil, err
	}

	path, err := s.resolveVaultPath(name)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); err == nil {
		return nil, &ErrState{Reason: fmt.Sprintf("vault '%s' already exists", name)}
	}

	// 1. Shard the master passphrase using SSS
	mnemonics, err := s.Split(ectx, path, threshold, shares, string(passphrase))
	if err != nil {
		return nil, fmt.Errorf("failed to shard passphrase: %w", err)
	}

	// 2. Open vault and save metadata
	store, err := s.Store.Open(path)
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

func (s *VaultService) Status(ectx *EngineContext, name string) (*VaultResult, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapVaultRead); err != nil {
		return nil, err
	}
	path, err := s.resolveVaultPath(name)
	if err != nil {
		return nil, err
	}

	store, err := s.Store.Open(path)
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

func (s *VaultService) Set(ectx *EngineContext, vaultPath string, entry *VaultEntry, passphrase []byte, pin string, overwrite bool) error {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapVaultWrite); err != nil {
		return err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := s.resolveVaultPath(vaultPath)
	if err != nil {
		return err
	}

	if err := ectx.Policy.ValidatePath(path); err != nil {
		return err
	}

	store, err := s.Store.Open(path)
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

// vaultAttempts is the sidecar data persisted alongside a vault to track failed auth attempts.
type vaultAttempts struct {
	Count int       `json:"count"`
	Since time.Time `json:"since"`
}

// sidecarPath returns the .attempts file path for a vault, validating that it
// stays within the configured vaults directory to prevent path traversal.
// Returns "" if the path is outside the allowed directory.
func (s *VaultService) sidecarPath(resolvedVaultPath string) string {
	vaultsDir := filepath.Clean(s.engine.Config.Paths.VaultsDir)
	clean := filepath.Clean(resolvedVaultPath)
	// Ensure the vault path is inside the configured vaults directory.
	rel, err := filepath.Rel(vaultsDir, clean)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "" // outside allowed directory — refuse to create sidecar
	}
	return clean + ".attempts"
}

func (s *VaultService) readAttempts(vaultPath string) vaultAttempts {
	p := s.sidecarPath(vaultPath)
	if p == "" {
		return vaultAttempts{}
	}
	data, err := os.ReadFile(p) // #nosec G304 — path validated by sidecarPath
	if err != nil {
		return vaultAttempts{}
	}
	var a vaultAttempts
	_ = json.Unmarshal(data, &a)
	return a
}

func (s *VaultService) writeAttempts(vaultPath string, a vaultAttempts) {
	sidecar := s.sidecarPath(vaultPath)
	if sidecar == "" {
		return
	}
	data, _ := json.Marshal(a)
	tmp := sidecar + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err == nil { // #nosec G306
		_ = os.Rename(tmp, sidecar)
	}
}

func (s *VaultService) clearAttempts(vaultPath string) {
	if p := s.sidecarPath(vaultPath); p != "" {
		_ = os.Remove(p)
	}
}

func (s *VaultService) checkLockout(vaultPath string) error {
	conf := s.engine.Config
	if conf == nil || conf.VaultMaxFailAttempts <= 0 {
		return nil
	}
	a := s.readAttempts(vaultPath)
	if a.Count < conf.VaultMaxFailAttempts {
		return nil
	}
	lockoutDur := time.Duration(conf.VaultLockoutMinutes) * time.Minute
	if lockoutDur <= 0 {
		lockoutDur = 15 * time.Minute
	}
	if time.Since(a.Since) < lockoutDur {
		return &ErrAuthentication{Reason: fmt.Sprintf("vault locked: too many failed attempts (%d/%d) — retry after %s",
			a.Count, conf.VaultMaxFailAttempts, a.Since.Add(lockoutDur).Format(time.RFC3339))}
	}
	// Lockout window has expired; clear and allow
	s.clearAttempts(vaultPath)
	return nil
}

func (s *VaultService) recordFailedAttempt(vaultPath string) {
	conf := s.engine.Config
	if conf == nil || conf.VaultMaxFailAttempts <= 0 {
		return
	}
	a := s.readAttempts(vaultPath)
	if a.Count == 0 {
		a.Since = time.Now()
	}
	a.Count++
	s.writeAttempts(vaultPath, a)
}

func (s *VaultService) Get(ectx *EngineContext, vaultPath string, service string, passphrase []byte, pin string) (*VaultEntry, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapVaultRead); err != nil {
		return nil, err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := s.resolveVaultPath(vaultPath)
	if err != nil {
		return nil, err
	}

	if err := ectx.Policy.ValidatePath(path); err != nil {
		return nil, err
	}

	if err := s.checkLockout(path); err != nil {
		return nil, err
	}

	store, err := s.Store.Open(path)
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
		s.engine.Logger.Info("Institutional vault detected: initiating quorum unlock", "vault", vaultPath, "peers", len(quorumPeers))
		responses, err := s.engine.QuorumRequest(ectx, "", quorumPeers, ActionVaultUnlock, vaultPath, "Consensus-based vault access requested")
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
		recovered, err := s.Recover(ectx, shares, vaultPath, "", "")
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

	var authErr *ErrAuthentication
	if isErrAuthentication(err, &authErr) {
		s.recordFailedAttempt(path)
	} else if err == nil {
		s.clearAttempts(path)
	}

	return entry, err
}

func (s *VaultService) Delete(ectx *EngineContext, name string) error {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapVaultDelete); err != nil {
		return err
	}
	path, err := s.resolveVaultPath(name)
	if err != nil {
		return err
	}
	if err := ectx.Policy.ValidatePath(path); err != nil {
		return err
	}

	return s.Store.DeleteVault(path)
}

func (s *VaultService) Rename(ectx *EngineContext, oldName, newName string) error {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapVaultWrite); err != nil {
		return err
	}
	oldPath, err := s.resolveVaultPath(oldName)
	if err != nil {
		return err
	}
	newPath, err := s.resolveVaultPath(newName)
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

func (s *VaultService) List(ectx *EngineContext, vaultPath string, passphrase []byte) ([]VaultListEntry, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapVaultRead); err != nil {
		return nil, err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := s.resolveVaultPath(vaultPath)
	if err != nil {
		return nil, err
	}
	if err := ectx.Policy.ValidatePath(path); err != nil {
		return nil, err
	}

	store, err := s.Store.Open(path)
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
		s.engine.Logger.Info("Institutional vault detected: initiating quorum unlock for listing", "vault", vaultPath)
		responses, err := s.engine.QuorumRequest(ectx, "", quorumPeers, ActionVaultUnlock, vaultPath, "Consensus-based vault listing requested")
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

		recovered, err := s.Recover(ectx, shares, vaultPath, "", "")
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

func (s *VaultService) Split(ectx *EngineContext, vaultPath string, threshold, shares int, passphrase string) ([]string, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapVaultRead); err != nil {
		return nil, err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := s.resolveVaultPath(vaultPath)
	if err != nil {
		return nil, err
	}
	return SplitVault(path, threshold, shares, passphrase)
}

func (s *VaultService) Recover(ectx *EngineContext, mnemonics []string, vaultPath string, output string, passphrase string) (string, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapVaultWrite); err != nil {
		return "", err
	}
	if vaultPath == "" {
		vaultPath = "default"
	}
	path, err := s.resolveVaultPath(vaultPath)
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
		entries, err := s.List(ectx, path, []byte(recoveredPass))
		if err != nil {
			return "", fmt.Errorf("failed to list entries from source vault: %w", err)
		}

		// Create/Open target vault
		outputPath, err := s.resolveVaultPath(output)
		if err != nil {
			return "", err
		}

		for _, entry := range entries {
			// Get full entry (with password)
			fullEntry, err := s.Get(ectx, path, entry.Service, []byte(recoveredPass), "")
			if err != nil {
				return "", fmt.Errorf("failed to get entry '%s': %w", entry.Service, err)
			}

			// Set in new vault
			err = s.Set(ectx, outputPath, fullEntry, []byte(recoveredPass), "", true)
			if err != nil {
				return "", fmt.Errorf("failed to set entry '%s' in recovered vault: %w", entry.Service, err)
			}
		}
	}

	return recoveredPass, nil
}

func (s *VaultService) CheckShards(ectx *EngineContext, mnemonics []string) (*VaultResult, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapVaultRead); err != nil {
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
			return nil, &ErrFormat{Reason: "shards have inconsistent thresholds"}
		}
	}

	return &VaultResult{
		Status:    "success",
		Threshold: threshold,
		Message:   fmt.Sprintf("%d of %d shards valid", len(mnemonics), threshold),
	}, nil
}

func (s *VaultService) Rotate(ectx *EngineContext, vaultPath string, oldPassphrase, newPassphrase []byte) error {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapVaultWrite); err != nil {
		return err
	}
	if _, err := s.resolveVaultPath(vaultPath); err != nil {
		return err
	}

	// 1. List all entries using old passphrase
	entries, err := s.List(ectx, vaultPath, oldPassphrase)
	if err != nil {
		return fmt.Errorf("failed to list entries for rotation: %w", err)
	}

	// 2. Extract full content of each entry
	var fullEntries []*VaultEntry
	for _, e := range entries {
		full, err := s.Get(ectx, vaultPath, e.Service, oldPassphrase, "")
		if err != nil {
			return fmt.Errorf("failed to extract entry '%s' for rotation: %w", e.Service, err)
		}
		fullEntries = append(fullEntries, full)
	}

	// 3. Re-save all entries using new passphrase
	for _, full := range fullEntries {
		if err := s.Set(ectx, vaultPath, full, newPassphrase, "", true); err != nil {
			return fmt.Errorf("failed to re-save entry '%s' with new passphrase: %w", full.Service, err)
		}
	}

	return nil
}

// --- Internal Helpers ---

func (s *VaultService) resolveVaultPath(name string) (string, error) {
	if filepath.IsAbs(name) {
		return name, nil
	}
	return filepath.Join(s.engine.Config.Paths.VaultsDir, name+".vault"), nil
}
