package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/awnumar/memguard"
)

func (e *Engine) Protect(ectx *EngineContext, inputName string, r io.Reader, w io.Writer, opts Options) (EncryptResult, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapProtect); err != nil {
		return EncryptResult{}, err
	}
	return e.ProtectStream(ectx, inputName, r, w, opts)
}

func (e *Engine) Unprotect(ectx *EngineContext, r io.Reader, w io.Writer, outPath string, opts Options) (DecryptResult, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapUnprotect); err != nil {
		return DecryptResult{}, err
	}
	return e.UnprotectStream(ectx, r, w, outPath, opts)
}

func (e *Engine) Sign(ectx *EngineContext, data []byte, privKey []byte) ([]byte, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapCrypto); err != nil {
		return nil, err
	}
	return SignData(data, privKey)
}

func (e *Engine) Verify(ectx *EngineContext, data []byte, sig []byte, pubKey []byte) (bool, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapCrypto); err != nil {
		return false, err
	}
	return VerifySignature(data, sig, pubKey), nil
}

func (e *Engine) Wrap(ectx *EngineContext, pubKey []byte) (DataKey, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapCrypto); err != nil {
		return DataKey{}, err
	}

	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return DataKey{}, fmt.Errorf("failed to generate DEK: %w", err)
	}
	defer SafeClear(dek)

	plaintext := make([]byte, len(dek))
	copy(plaintext, dek)

	profile := DefaultProfile()
	dekEnclave := memguard.NewEnclave(dek)
	wrapped, err := profile.WrapFEK(pubKey, 0, dekEnclave)
	if err != nil {
		return DataKey{}, err
	}

	return DataKey{
		Plaintext: plaintext,
		Wrapped:   wrapped,
	}, nil
}

func (e *Engine) Unwrap(ectx *EngineContext, wrappedKey []byte, privKey []byte) ([]byte, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapCrypto); err != nil {
		return nil, err
	}

	profile := DefaultProfile()
	defer SafeClear(privKey)

	dekEnclave, err := profile.UnwrapFEK(privKey, 0, wrappedKey)
	if err != nil {
		return nil, err
	}

	dek, err := dekEnclave.Open()
	if err != nil {
		return nil, err
	}
	defer dek.Destroy()

	plaintext := make([]byte, dek.Size())
	copy(plaintext, dek.Bytes())

	return plaintext, nil
}

func (e *Engine) RegisterProfile(ectx *EngineContext, name string, dp *DynamicProfile) error {
	ectx = e.context(ectx)
	if !ectx.Policy.AllowConfigModification() {
		return &ErrPolicyViolation{Reason: "profile registration is prohibited under the active policy"}
	}
	if e.Config.Profiles == nil {
		e.Config.Profiles = make(map[string]*DynamicProfile)
	}
	e.Config.Profiles[name] = dp
	RegisterProfile(dp)
	return e.Config.Save()
}

func (e *Engine) RemoveProfile(ectx *EngineContext, name string) error {
	ectx = e.context(ectx)
	if !ectx.Policy.AllowConfigModification() {
		return &ErrPolicyViolation{Reason: "profile removal is prohibited under the active policy"}
	}
	if _, ok := e.Config.Profiles[name]; !ok {
		return fmt.Errorf("profile '%s' not found", name)
	}
	delete(e.Config.Profiles, name)
	return e.Config.Save()
}

func (e *Engine) Inspect(_ *EngineContext, in io.Reader, stealth bool) (*HeaderInfo, error) {
	magic, profileID, flags, recipients, err := ReadHeader(in, stealth)
	if err != nil {
		return nil, err
	}

	info := &HeaderInfo{
		Magic:          magic,
		ProfileID:      profileID,
		Flags:          flags,
		RecipientCount: recipients,
		Compressed:     flags&FlagCompress != 0,
		IsArchive:      flags&FlagArchive != 0,
		IsSigned:       flags&FlagSigned != 0,
		IsStealth:      stealth || flags&FlagStealth != 0,
	}

	if magic == MagicHeader {
		info.Type = "symmetric"
	} else if magic == MagicHeaderAsym {
		info.Type = "asymmetric"
	}

	if info.IsStealth {
		info.Type = "stealth"
	}

	profile, err := GetProfile(profileID, nil)
	if err == nil {
		info.KEMAlgorithm = profile.KEMName()
		info.SIGAlgorithm = profile.SIGName()

		if v1, ok := profile.(*ProfileV1); ok {
			info.KDFDetails = fmt.Sprintf("Argon2id (t=%d, m=%d, p=%d)", v1.ArgonTime, v1.ArgonMem, v1.ArgonThrd)
		}
	}

	return info, nil
}
