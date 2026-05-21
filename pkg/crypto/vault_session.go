package crypto

import (
	"sync"
	"time"
)

const defaultVaultSessionTTL = 5 * time.Minute

// vaultSession caches a derived vault key for the lifetime of a TTL window,
// eliminating per-operation Argon2id cost (~26 ms) after VaultUnlock is called.
// The key is a plain []byte; SafeClear wipes it on expiry or explicit lock.
type vaultSession struct {
	mu        sync.Mutex
	key       []byte
	expiresAt time.Time
	timer     *time.Timer
}

// borrowKey returns a copy of the cached key if the session is still valid,
// nil otherwise. The caller must SafeClear the returned slice when done.
func (s *vaultSession) borrowKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) == 0 || time.Now().After(s.expiresAt) {
		return nil
	}
	out := make([]byte, len(s.key))
	copy(out, s.key)
	return out
}

// wipe zeros the key and stops the expiry timer. Safe to call multiple times.
func (s *vaultSession) wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	SafeClear(s.key)
	s.key = nil
}

// Unlock derives the vault key once and caches it for ttlSeconds.
// If ttlSeconds is 0, the engine config VaultSessionTTLSeconds is used;
// if that is also 0, the default (5 min) applies.
// Subsequent Get/Set/List calls will bypass Argon2id for the session lifetime.
func (s *VaultService) Unlock(ectx *EngineContext, name string, passphrase []byte, ttlSeconds int) error {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapVaultRead); err != nil {
		return err
	}

	path, err := s.resolveVaultPath(name)
	if err != nil {
		return err
	}
	if err := ectx.Policy.ValidatePath(path); err != nil {
		return err
	}
	if err := s.checkLockout(path); err != nil {
		return err
	}

	// Open the vault to read the salt — needed to derive the key.
	store, err := s.Store.Open(path)
	if err != nil {
		return err
	}
	// Copy the salt within the transaction — bbolt byte slices are mmap-backed
	// and become invalid once the transaction (and store) is closed.
	var salt []byte
	_ = store.View(func(tx Transaction) error {
		raw := tx.Get(metaBucket, saltKey)
		if raw != nil {
			salt = make([]byte, len(raw))
			copy(salt, raw)
		}
		return nil
	})
	store.Close()

	if salt == nil {
		// Vault is empty (no salt written yet). Skip caching — the first Set
		// will create a fresh salt and we will derive there.
		return nil
	}

	key := DeriveVaultKey(passphrase, salt)

	ttl := defaultVaultSessionTTL
	if ttlSeconds > 0 {
		ttl = time.Duration(ttlSeconds) * time.Second
	} else if s.engine.Config != nil && s.engine.Config.VaultSessionTTLSeconds > 0 {
		ttl = time.Duration(s.engine.Config.VaultSessionTTLSeconds) * time.Second
	}

	sess := &vaultSession{
		key:       key,
		expiresAt: time.Now().Add(ttl),
	}
	sess.timer = time.AfterFunc(ttl, func() { s.expireSession(path) })

	s.sessMu.Lock()
	if existing, ok := s.sessions[path]; ok {
		existing.wipe()
	}
	s.sessions[path] = sess
	s.sessMu.Unlock()

	s.engine.Logger.Info("vault session unlocked", "vault", name, "ttl", ttl.String())
	return nil
}

// Lock immediately wipes the cached key for the named vault.
func (s *VaultService) Lock(ectx *EngineContext, name string) error {
	path, err := s.resolveVaultPath(name)
	if err != nil {
		return err
	}
	s.expireSession(path)
	s.engine.Logger.Info("vault session locked", "vault", name)
	return nil
}

// LockAll wipes every active session. Called from engine.Close().
func (s *VaultService) LockAll() {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	for path, sess := range s.sessions {
		sess.wipe()
		delete(s.sessions, path)
	}
}

// expireSession is the shared path for TTL expiry and manual lock.
func (s *VaultService) expireSession(path string) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if sess, ok := s.sessions[path]; ok {
		sess.wipe()
		delete(s.sessions, path)
	}
}

// sessionKey returns a copy of the active session key, or nil if no session
// exists or has expired. The caller must SafeClear the returned slice.
func (s *VaultService) sessionKey(path string) []byte {
	s.sessMu.RLock()
	sess, ok := s.sessions[path]
	s.sessMu.RUnlock()
	if !ok {
		return nil
	}
	return sess.borrowKey()
}
