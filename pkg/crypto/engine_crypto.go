package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/awnumar/memguard"
)

// --- Engine Wrappers ---

func (e *Engine) Protect(ectx *EngineContext, inputName string, r io.Reader, w io.Writer, opts Options) (EncryptResult, error) {
	return e.Crypto.Protect(ectx, inputName, r, w, opts)
}

func (e *Engine) Unprotect(ectx *EngineContext, r io.Reader, w io.Writer, outPath string, opts Options) (DecryptResult, error) {
	return e.Crypto.Unprotect(ectx, r, w, outPath, opts)
}

func (e *Engine) Sign(ectx *EngineContext, data []byte, privKey []byte) ([]byte, error) {
	return e.Crypto.Sign(ectx, data, privKey)
}

func (e *Engine) Verify(ectx *EngineContext, data []byte, sig []byte, pubKey []byte) (bool, error) {
	return e.Crypto.Verify(ectx, data, sig, pubKey)
}

func (e *Engine) Wrap(ectx *EngineContext, pubKey []byte) (DataKey, error) {
	return e.Crypto.Wrap(ectx, pubKey)
}

func (e *Engine) Unwrap(ectx *EngineContext, wrappedKey []byte, privKey []byte) ([]byte, error) {
	return e.Crypto.Unwrap(ectx, wrappedKey, privKey)
}

func (e *Engine) RegisterProfile(ectx *EngineContext, name string, dp *DynamicProfile) error {
	return e.Crypto.RegisterProfile(ectx, name, dp)
}

func (e *Engine) RemoveProfile(ectx *EngineContext, name string) error {
	return e.Crypto.RemoveProfile(ectx, name)
}

func (e *Engine) Inspect(ectx *EngineContext, in io.Reader, stealth bool) (*HeaderInfo, error) {
	return e.Crypto.Inspect(ectx, in, stealth)
}

// --- CryptoService Implementation ---

func (s *CryptoService) Protect(ectx *EngineContext, inputName string, r io.Reader, w io.Writer, opts Options) (EncryptResult, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapProtect); err != nil {
		return EncryptResult{}, err
	}
	return s.engine.ProtectStream(ectx, inputName, r, w, opts)
}

func (s *CryptoService) Unprotect(ectx *EngineContext, r io.Reader, w io.Writer, outPath string, opts Options) (DecryptResult, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapUnprotect); err != nil {
		return DecryptResult{}, err
	}
	return s.engine.UnprotectStream(ectx, r, w, outPath, opts)
}

func (s *CryptoService) Sign(ectx *EngineContext, data []byte, privKey []byte) ([]byte, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapCrypto); err != nil {
		return nil, err
	}
	return SignData(data, privKey)
}

func (s *CryptoService) Verify(ectx *EngineContext, data []byte, sig []byte, pubKey []byte) (bool, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapCrypto); err != nil {
		return false, err
	}
	return VerifySignature(data, sig, pubKey), nil
}

func (s *CryptoService) Wrap(ectx *EngineContext, pubKey []byte) (DataKey, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapCrypto); err != nil {
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

func (s *CryptoService) Unwrap(ectx *EngineContext, wrappedKey []byte, privKey []byte) ([]byte, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapCrypto); err != nil {
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

func (s *CryptoService) RegisterProfile(ectx *EngineContext, name string, dp *DynamicProfile) error {
	ectx = s.engine.context(ectx)
	if !ectx.Policy.AllowConfigModification() {
		return &ErrPolicyViolation{
			Reason:     "profile registration is prohibited under the active policy",
			PolicyName: ectx.Policy.Name(),
		}
	}
	if s.engine.Config.Profiles == nil {
		s.engine.Config.Profiles = make(map[string]*DynamicProfile)
	}
	s.engine.Config.Profiles[name] = dp
	RegisterProfile(dp)
	return s.engine.Config.Save()
}

func (s *CryptoService) RemoveProfile(ectx *EngineContext, name string) error {
	ectx = s.engine.context(ectx)
	if !ectx.Policy.AllowConfigModification() {
		return &ErrPolicyViolation{
			Reason:     "profile removal is prohibited under the active policy",
			PolicyName: ectx.Policy.Name(),
		}
	}
	if _, ok := s.engine.Config.Profiles[name]; !ok {
		return fmt.Errorf("profile '%s' not found", name)
	}
	delete(s.engine.Config.Profiles, name)
	return s.engine.Config.Save()
}

func (s *CryptoService) Inspect(_ *EngineContext, in io.Reader, stealth bool) (*HeaderInfo, error) {
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
