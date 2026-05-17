package crypto

// --- Engine Wrappers ---

func (e *Engine) IdentityActive(ectx *EngineContext) ([]string, error) {
	return e.Identity.Active(ectx)
}

func (e *Engine) IdentityInfo(ectx *EngineContext, name string) (*IdentityInfoResult, error) {
	return e.Identity.Info(ectx, name)
}

func (e *Engine) IdentityRename(ectx *EngineContext, oldName, newName string) error {
	return e.Identity.Rename(ectx, oldName, newName)
}

func (e *Engine) IdentitySplit(ectx *EngineContext, name string, threshold, shares int, passphrase string) ([]string, error) {
	return e.Identity.Split(ectx, name, threshold, shares, passphrase)
}

func (e *Engine) IdentityPublish(ectx *EngineContext, handle string, opts IdentityPublishOptions) error {
	return e.Identity.Publish(ectx, handle, opts)
}

func (e *Engine) CreateIdentity(ectx *EngineContext, output string, passphrase []byte, pin string, agent bool, profile string) (*IdentityResult, error) {
	return e.Identity.Create(ectx, output, passphrase, pin, agent, profile)
}

func (e *Engine) IdentityCombine(ectx *EngineContext, mnemonics []string, output, passphrase string, noPassword bool) (string, error) {
	return e.Identity.Combine(ectx, mnemonics, output, passphrase, noPassword)
}

func (e *Engine) ResolvePublicKey(ectx *EngineContext, input string, tofu bool) ([]byte, error) {
	return e.Identity.ResolvePublicKey(ectx, input, tofu)
}

func (e *Engine) LoadPrivateKey(ectx *EngineContext, path string, passphrase []byte, pin string, agent bool) ([]byte, error) {
	return e.Identity.LoadPrivateKey(ectx, path, passphrase, pin, agent)
}

func (e *Engine) LoadIdentity(ectx *EngineContext, name string, passphrase []byte, pin string, agent bool) (*Identity, error) {
	return e.Identity.LoadIdentity(ectx, name, passphrase, pin, agent)
}

func (e *Engine) ResolveKeyPath(ectx *EngineContext, path, envVar string) string {
	return e.Identity.ResolveKeyPath(ectx, path, envVar)
}

func (e *Engine) ResolveBaseKeyPath(ectx *EngineContext, name string) (string, string, error) {
	return e.Identity.ResolveBaseKeyPath(ectx, name)
}

func (e *Engine) GeneratePassword(ectx *EngineContext, length int, noSymbols bool) (string, error) {
	return GeneratePassword(length, noSymbols)
}

func (e *Engine) GeneratePassphrase(ectx *EngineContext, words int, separator string) (string, error) {
	return GeneratePassphrase(words, separator)
}

func (e *Engine) SecureDelete(path string) error {
	e.Logger.Debug("securely deleting path", "path", path)
	return e.SecureDeleteStream(path)
}

// --- IdentityService Implementation ---

func (s *IdentityService) Active(ectx *EngineContext) ([]string, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return s.Mgr.ListActiveIdentities()
}

func (s *IdentityService) Info(ectx *EngineContext, name string) (*IdentityInfoResult, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return s.Mgr.GetIdentityInfo(name)
}

func (s *IdentityService) Rename(ectx *EngineContext, oldName, newName string) error {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapIdentity); err != nil {
		return err
	}
	return s.Mgr.RenameIdentity(oldName, newName)
}

func (s *IdentityService) Split(ectx *EngineContext, name string, threshold, shares int, passphrase string) ([]string, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return s.Mgr.SplitIdentity(name, threshold, shares, passphrase)
}

func (s *IdentityService) Publish(ectx *EngineContext, handle string, opts IdentityPublishOptions) error {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapIdentity); err != nil {
		return err
	}
	if err := s.engine.ensureContacts(); err != nil {
		return err
	}
	return s.Mgr.IdentityPublish(ectx.Context, handle, opts)
}

func (s *IdentityService) Create(ectx *EngineContext, output string, passphrase []byte, pin string, agent bool, profile string) (*IdentityResult, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return s.Mgr.CreateIdentity(output, passphrase, pin, agent, profile)
}

func (s *IdentityService) Combine(ectx *EngineContext, mnemonics []string, output, passphrase string, noPassword bool) (string, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapIdentity); err != nil {
		return "", err
	}
	return s.Mgr.CombineIdentity(mnemonics, output, passphrase, noPassword)
}

func (s *IdentityService) ResolvePublicKey(ectx *EngineContext, input string, tofu bool) ([]byte, error) {
	return s.Mgr.ResolvePublicKey(input, tofu)
}

func (s *IdentityService) LoadPrivateKey(ectx *EngineContext, path string, passphrase []byte, pin string, agent bool) ([]byte, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return s.Mgr.LoadPrivateKey(path, passphrase, pin, agent)
}

func (s *IdentityService) LoadIdentity(ectx *EngineContext, name string, passphrase []byte, pin string, agent bool) (*Identity, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return s.Mgr.LoadIdentity(name, passphrase, pin, agent)
}

func (s *IdentityService) ResolveKeyPath(ectx *EngineContext, path, envVar string) string {
	return s.Mgr.ResolveKeyPath(path, envVar)
}

func (s *IdentityService) ResolveBaseKeyPath(ectx *EngineContext, name string) (string, string, error) {
	return s.Mgr.ResolveBaseKeyPath(name)
}
