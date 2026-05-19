package crypto

import (
	"io"
	"log/slog"
)

// BaseEngine implements MaknoonEngine by delegating all calls to an internal engine.
// This is used as a base for decorators (like AuditEngine) to prevent drift.
type BaseEngine struct {
	Engine MaknoonEngine
}

// Protector
func (e *BaseEngine) Protect(ectx *EngineContext, inputName string, r io.Reader, w io.Writer, opts Options) (EncryptResult, error) {
	return e.Engine.Protect(ectx, inputName, r, w, opts)
}
func (e *BaseEngine) Unprotect(ectx *EngineContext, r io.Reader, w io.Writer, outPath string, opts Options) (DecryptResult, error) {
	return e.Engine.Unprotect(ectx, r, w, outPath, opts)
}
func (e *BaseEngine) FinalizeRestoration(ectx *EngineContext, pr io.Reader, w io.Writer, flags byte, outPath string, logger *slog.Logger) error {
	return e.Engine.FinalizeRestoration(ectx, pr, w, flags, outPath, logger)
}
func (e *BaseEngine) LoadCustomProfile(ectx *EngineContext, path string) (*DynamicProfile, error) {
	return e.Engine.LoadCustomProfile(ectx, path)
}
func (e *BaseEngine) GenerateRandomProfile(ectx *EngineContext, id byte) *DynamicProfile {
	return e.Engine.GenerateRandomProfile(ectx, id)
}
func (e *BaseEngine) ValidateProfile(ectx *EngineContext, p *DynamicProfile) error {
	return e.Engine.ValidateProfile(ectx, p)
}

// IdentityService
func (e *BaseEngine) IdentityActive(ectx *EngineContext) ([]string, error) {
	return e.Engine.IdentityActive(ectx)
}
func (e *BaseEngine) IdentityInfo(ectx *EngineContext, name string) (*IdentityInfoResult, error) {
	return e.Engine.IdentityInfo(ectx, name)
}
func (e *BaseEngine) IdentityDelete(ectx *EngineContext, name string) error {
	return e.Engine.IdentityDelete(ectx, name)
}
func (e *BaseEngine) IdentityRename(ectx *EngineContext, oldName, newName string) error {
	return e.Engine.IdentityRename(ectx, oldName, newName)
}
func (e *BaseEngine) IdentitySplit(ectx *EngineContext, name string, threshold, shares int, passphrase string) ([]string, error) {
	return e.Engine.IdentitySplit(ectx, name, threshold, shares, passphrase)
}
func (e *BaseEngine) IdentityCombine(ectx *EngineContext, mnemonics []string, output string, passphrase string, noPassword bool) (string, error) {
	return e.Engine.IdentityCombine(ectx, mnemonics, output, passphrase, noPassword)
}
func (e *BaseEngine) IdentityPublish(ectx *EngineContext, handle string, opts IdentityPublishOptions) error {
	return e.Engine.IdentityPublish(ectx, handle, opts)
}
func (e *BaseEngine) CreateIdentity(ectx *EngineContext, output string, passphrase []byte, pin string, agent bool, profile string) (*IdentityResult, error) {
	return e.Engine.CreateIdentity(ectx, output, passphrase, pin, agent, profile)
}
func (e *BaseEngine) ContactAdd(ectx *EngineContext, petname, kemPub, sigPub, note string) error {
	return e.Engine.ContactAdd(ectx, petname, kemPub, sigPub, note)
}
func (e *BaseEngine) ContactList(ectx *EngineContext) ([]*Contact, error) {
	return e.Engine.ContactList(ectx)
}
func (e *BaseEngine) ContactDelete(ectx *EngineContext, petname string) error {
	return e.Engine.ContactDelete(ectx, petname)
}
func (e *BaseEngine) ResolvePublicKey(ectx *EngineContext, input string, tofu bool) ([]byte, error) {
	return e.Engine.ResolvePublicKey(ectx, input, tofu)
}
func (e *BaseEngine) LoadPrivateKey(ectx *EngineContext, path string, passphrase []byte, pin string, agent bool) ([]byte, error) {
	return e.Engine.LoadPrivateKey(ectx, path, passphrase, pin, agent)
}
func (e *BaseEngine) LoadIdentity(ectx *EngineContext, name string, passphrase []byte, pin string, agent bool) (*Identity, error) {
	return e.Engine.LoadIdentity(ectx, name, passphrase, pin, agent)
}
func (e *BaseEngine) ResolveKeyPath(ectx *EngineContext, path, envVar string) string {
	return e.Engine.ResolveKeyPath(ectx, path, envVar)
}
func (e *BaseEngine) ResolveBaseKeyPath(ectx *EngineContext, name string) (string, string, error) {
	return e.Engine.ResolveBaseKeyPath(ectx, name)
}

// VaultManager
func (e *BaseEngine) VaultInitInstitutional(ectx *EngineContext, name string, threshold, shares int, peerIDs []string, passphrase []byte) (*VaultResult, error) {
	return e.Engine.VaultInitInstitutional(ectx, name, threshold, shares, peerIDs, passphrase)
}
func (e *BaseEngine) VaultStatus(ectx *EngineContext, name string) (*VaultResult, error) {
	return e.Engine.VaultStatus(ectx, name)
}
func (e *BaseEngine) VaultGet(ectx *EngineContext, vaultPath string, service string, passphrase []byte, pin string) (*VaultEntry, error) {
	return e.Engine.VaultGet(ectx, vaultPath, service, passphrase, pin)
}
func (e *BaseEngine) VaultSet(ectx *EngineContext, vaultPath string, entry *VaultEntry, passphrase []byte, pin string, overwrite bool) error {
	return e.Engine.VaultSet(ectx, vaultPath, entry, passphrase, pin, overwrite)
}
func (e *BaseEngine) VaultRename(ectx *EngineContext, oldName, newName string) error {
	return e.Engine.VaultRename(ectx, oldName, newName)
}
func (e *BaseEngine) VaultDelete(ectx *EngineContext, name string) error {
	return e.Engine.VaultDelete(ectx, name)
}
func (e *BaseEngine) VaultList(ectx *EngineContext, vaultPath string, passphrase []byte) ([]VaultListEntry, error) {
	return e.Engine.VaultList(ectx, vaultPath, passphrase)
}
func (e *BaseEngine) VaultRotate(ectx *EngineContext, vaultPath string, oldPassphrase, newPassphrase []byte) error {
	return e.Engine.VaultRotate(ectx, vaultPath, oldPassphrase, newPassphrase)
}
func (e *BaseEngine) VaultCheckShards(ectx *EngineContext, mnemonics []string) (*VaultResult, error) {
	return e.Engine.VaultCheckShards(ectx, mnemonics)
}
func (e *BaseEngine) VaultSplit(ectx *EngineContext, vaultPath string, threshold, shares int, passphrase string) ([]string, error) {
	return e.Engine.VaultSplit(ectx, vaultPath, threshold, shares, passphrase)
}
func (e *BaseEngine) VaultRecover(ectx *EngineContext, mnemonics []string, vaultPath string, output string, passphrase string) (string, error) {
	return e.Engine.VaultRecover(ectx, mnemonics, vaultPath, output, passphrase)
}

// Utils
func (e *BaseEngine) GeneratePassword(ectx *EngineContext, length int, noSymbols bool) (string, error) {
	return e.Engine.GeneratePassword(ectx, length, noSymbols)
}
func (e *BaseEngine) GeneratePassphrase(ectx *EngineContext, words int, separator string) (string, error) {
	return e.Engine.GeneratePassphrase(ectx, words, separator)
}
func (e *BaseEngine) SecureDelete(path string) error {
	return e.Engine.SecureDelete(path)
}

// StateProvider
func (e *BaseEngine) GetPolicy() SecurityPolicy { return e.Engine.GetPolicy() }
func (e *BaseEngine) GetConfig() *Config        { return e.Engine.GetConfig() }
func (e *BaseEngine) UpdateConfig(ectx *EngineContext, newConf *Config) error {
	return e.Engine.UpdateConfig(ectx, newConf)
}
func (e *BaseEngine) RegisterProfile(ectx *EngineContext, name string, dp *DynamicProfile) error {
	return e.Engine.RegisterProfile(ectx, name, dp)
}
func (e *BaseEngine) RemoveProfile(ectx *EngineContext, name string) error {
	return e.Engine.RemoveProfile(ectx, name)
}
func (e *BaseEngine) Diagnostic() DiagnosticResult { return e.Engine.Diagnostic() }
func (e *BaseEngine) NetworkStatus(ectx *EngineContext) (NetStatusResult, error) {
	return e.Engine.NetworkStatus(ectx)
}
func (e *BaseEngine) AuditExport(ectx *EngineContext) ([]AuditEntry, error) {
	return e.Engine.AuditExport(ectx)
}

// Inspector
func (e *BaseEngine) Inspect(ectx *EngineContext, in io.Reader, stealth bool) (*HeaderInfo, error) {
	return e.Engine.Inspect(ectx, in, stealth)
}

// Signer
func (e *BaseEngine) Sign(ectx *EngineContext, data []byte, privKey []byte) ([]byte, error) {
	return e.Engine.Sign(ectx, data, privKey)
}
func (e *BaseEngine) Verify(ectx *EngineContext, data []byte, sig []byte, pubKey []byte) (bool, error) {
	return e.Engine.Verify(ectx, data, sig, pubKey)
}
func (e *BaseEngine) Aggregate(ectx *EngineContext, signatures [][]byte) ([]byte, error) {
	return e.Engine.Aggregate(ectx, signatures)
}
func (e *BaseEngine) VerifyThreshold(ectx *EngineContext, data []byte, aggregateSig []byte, authorizedKeys [][]byte, threshold int) (bool, error) {
	return e.Engine.VerifyThreshold(ectx, data, aggregateSig, authorizedKeys, threshold)
}

// KMSService
func (e *BaseEngine) Wrap(ectx *EngineContext, pubKey []byte) (DataKey, error) {
	return e.Engine.Wrap(ectx, pubKey)
}
func (e *BaseEngine) Unwrap(ectx *EngineContext, wrappedKey []byte, privKey []byte) ([]byte, error) {
	return e.Engine.Unwrap(ectx, wrappedKey, privKey)
}

// DispersalService
func (e *BaseEngine) ReassembleFragments(srcDir string, w io.Writer, authorizedPubKey []byte) error {
	return e.Engine.ReassembleFragments(srcDir, w, authorizedPubKey)
}

func (e *BaseEngine) Close() error {
	return e.Engine.Close()
}
