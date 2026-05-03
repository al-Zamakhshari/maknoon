package crypto

import ()

func (e *Engine) IdentityActive(ectx *EngineContext) ([]string, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return e.Identities.ListActiveIdentities()
}

func (e *Engine) IdentityInfo(ectx *EngineContext, name string) (*IdentityInfoResult, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return e.Identities.GetIdentityInfo(name)
}

func (e *Engine) IdentityRename(ectx *EngineContext, oldName, newName string) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return err
	}
	return e.Identities.RenameIdentity(oldName, newName)
}

func (e *Engine) IdentitySplit(ectx *EngineContext, name string, threshold, shares int, passphrase string) ([]string, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return e.Identities.SplitIdentity(name, threshold, shares, passphrase)
}

func (e *Engine) IdentityPublish(ectx *EngineContext, handle string, opts IdentityPublishOptions) error {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return err
	}
	if err := e.ensureContacts(); err != nil {
		return err
	}
	return e.Identities.IdentityPublish(ectx.Context, handle, opts)
}

func (e *Engine) CreateIdentity(ectx *EngineContext, output string, passphrase []byte, pin string, agent bool, profile string) (*IdentityResult, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return e.Identities.CreateIdentity(output, passphrase, pin, agent, profile)
}

func (e *Engine) IdentityCombine(ectx *EngineContext, mnemonics []string, output, passphrase string, noPassword bool) (string, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return "", err
	}
	return e.Identities.CombineIdentity(mnemonics, output, passphrase, noPassword)
}

func (e *Engine) ResolvePublicKey(ectx *EngineContext, input string, tofu bool) ([]byte, error) {
	return e.Identities.ResolvePublicKey(input, tofu)
}

func (e *Engine) LoadPrivateKey(ectx *EngineContext, path string, passphrase []byte, pin string, agent bool) ([]byte, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapIdentity); err != nil {
		return nil, err
	}
	return e.Identities.LoadPrivateKey(path, passphrase, pin, agent)
}

func (e *Engine) ResolveKeyPath(ectx *EngineContext, path, envVar string) string {
	return e.Identities.ResolveKeyPath(path, envVar)
}

func (e *Engine) ResolveBaseKeyPath(ectx *EngineContext, name string) (string, string, error) {
	return e.Identities.ResolveBaseKeyPath(name)
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
