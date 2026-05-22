package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/awnumar/memguard"
)

// --- Engine Wrappers ---

func (e *Engine) Protect(ectx *EngineContext, inputName string, r io.Reader, w io.Writer, opts Options) (EncryptResult, error) {
	return e.Crypto.Protect(ectx, inputName, r, w, opts)
}

func (e *Engine) ProtectDirectory(ectx *EngineContext, inputDir, outputDir string, opts Options) (*RecursiveEncryptResult, error) {
	return e.Crypto.ProtectDirectory(ectx, inputDir, outputDir, opts)
}

func (e *Engine) ProtectFiles(ectx *EngineContext, files []string, outputDir string, opts Options) (*RecursiveEncryptResult, error) {
	return e.Crypto.ProtectFiles(ectx, files, outputDir, opts)
}

func (e *Engine) DecryptFiles(ectx *EngineContext, files []string, outputDir string, opts Options) (*RecursiveDecryptResult, error) {
	return e.Crypto.DecryptFiles(ectx, files, outputDir, opts)
}

func (e *Engine) DecryptDirectory(ectx *EngineContext, inputDir, outputDir string, opts Options) (*RecursiveDecryptResult, error) {
	return e.Crypto.DecryptDirectory(ectx, inputDir, outputDir, opts)
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

// ProtectDirectory encrypts every file in inputDir individually, writing
// output alongside each file (path + ".makn") or into outputDir when set.
// On the passphrase path it auto-derives a session key once so Argon2id runs
// exactly once regardless of how many files the directory contains.
func (s *CryptoService) ProtectDirectory(ectx *EngineContext, inputDir, outputDir string, opts Options) (*RecursiveEncryptResult, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapProtect); err != nil {
		return nil, err
	}

	cleanDir := filepath.Clean(inputDir)
	if err := ectx.Policy.ValidatePath(cleanDir); err != nil {
		return nil, err
	}
	info, err := os.Stat(cleanDir)
	if err != nil || !info.IsDir() {
		return nil, &ErrIO{Path: inputDir, Reason: "not a directory"}
	}

	// Auto-derive a session key when using a passphrase so Argon2id runs once
	// for the entire directory rather than once per file.
	fileOpts := opts
	var sessionKeyDerived bool
	if len(opts.Recipients) == 0 && len(opts.SessionKey) == 0 && len(opts.Passphrase) > 0 {
		key, salt, err := DeriveSessionKey(opts.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("session key derivation failed: %w", err)
		}
		defer SafeClear(key)
		fileOpts.SessionKey = key
		fileOpts.SessionSalt = salt
		fileOpts.Passphrase = nil
		sessionKeyDerived = true
	}

	result := &RecursiveEncryptResult{SessionKeyDerived: sessionKeyDerived}

	walkErr := filepath.WalkDir(cleanDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Skip files that are already encrypted.
		if strings.HasSuffix(path, ".makn") {
			result.Skipped = append(result.Skipped, path)
			return nil
		}

		rel, err := filepath.Rel(cleanDir, path)
		if err != nil {
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			return nil
		}

		var outPath string
		if outputDir != "" {
			outPath = filepath.Join(filepath.Clean(outputDir), rel+".makn")
		} else {
			outPath = path + ".makn"
		}

		if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			return nil
		}

		in, err := os.Open(path)
		if err != nil {
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			return nil
		}
		defer in.Close()

		fi, _ := in.Stat()
		fileBytes := fi.Size()

		out, err := os.Create(outPath)
		if err != nil {
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			return nil
		}
		defer out.Close()

		if _, err := s.engine.ProtectStream(ectx, filepath.Base(path), in, out, fileOpts); err != nil {
			_ = os.Remove(outPath)
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			return nil
		}

		result.Encrypted = append(result.Encrypted, RecursiveFileResult{
			Input:  path,
			Output: outPath,
			Bytes:  fileBytes,
		})
		result.TotalBytes += fileBytes
		return nil
	})

	if walkErr != nil {
		return nil, walkErr
	}

	result.TotalFiles = len(result.Encrypted)
	result.Status = "success"
	if len(result.Errors) > 0 {
		result.Status = "partial"
	}
	return result, nil
}

// ProtectFiles encrypts a list of explicit file paths individually, auto-deriving
// a session key on the passphrase path so Argon2id runs once for the whole list.
// outputDir, when set, is where the .makn files are written; otherwise each file
// gains a .makn suffix in its original directory.
func (s *CryptoService) ProtectFiles(ectx *EngineContext, files []string, outputDir string, opts Options) (*RecursiveEncryptResult, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapProtect); err != nil {
		return nil, err
	}

	fileOpts := opts
	var sessionKeyDerived bool
	if len(opts.Recipients) == 0 && len(opts.SessionKey) == 0 && len(opts.Passphrase) > 0 {
		key, salt, err := DeriveSessionKey(opts.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("session key derivation failed: %w", err)
		}
		defer SafeClear(key)
		fileOpts.SessionKey = key
		fileOpts.SessionSalt = salt
		fileOpts.Passphrase = nil
		sessionKeyDerived = true
	}

	result := &RecursiveEncryptResult{SessionKeyDerived: sessionKeyDerived}

	for _, path := range files {
		cleanPath := filepath.Clean(path)
		if err := ectx.Policy.ValidatePath(cleanPath); err != nil {
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			continue
		}
		if strings.HasSuffix(cleanPath, ".makn") {
			result.Skipped = append(result.Skipped, path)
			continue
		}

		var outPath string
		if outputDir != "" {
			outPath = filepath.Join(filepath.Clean(outputDir), filepath.Base(cleanPath)+".makn")
		} else {
			outPath = cleanPath + ".makn"
		}

		in, err := os.Open(cleanPath)
		if err != nil {
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			continue
		}
		fi, _ := in.Stat()
		fileBytes := fi.Size()

		out, err := os.Create(outPath)
		if err != nil {
			in.Close()
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			continue
		}

		if _, err := s.engine.ProtectStream(ectx, filepath.Base(cleanPath), in, out, fileOpts); err != nil {
			in.Close()
			out.Close()
			_ = os.Remove(outPath)
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			continue
		}
		in.Close()
		out.Close()

		result.Encrypted = append(result.Encrypted, RecursiveFileResult{
			Input: path, Output: outPath, Bytes: fileBytes,
		})
		result.TotalBytes += fileBytes
	}

	result.TotalFiles = len(result.Encrypted)
	result.Status = "success"
	if len(result.Errors) > 0 {
		result.Status = "partial"
	}
	return result, nil
}

// DecryptFiles decrypts a list of .makn files individually.
// Output for each file strips the .makn suffix; if outputDir is set, files land
// there preserving their base names. Non-zero exit (partial status) when any
// file fails. For session-key-encrypted batches, pass opts.SessionKey to avoid
// per-file KDF entirely; passphrase-based decryption pays Argon2id per file.
func (s *CryptoService) DecryptFiles(ectx *EngineContext, files []string, outputDir string, opts Options) (*RecursiveDecryptResult, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapUnprotect); err != nil {
		return nil, err
	}

	result := &RecursiveDecryptResult{}

	for _, path := range files {
		cleanPath := filepath.Clean(path)
		if err := ectx.Policy.ValidatePath(cleanPath); err != nil {
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			continue
		}

		base := filepath.Base(cleanPath)
		stripped := strings.TrimSuffix(base, ".makn")
		var outPath string
		if outputDir != "" {
			outPath = filepath.Join(filepath.Clean(outputDir), stripped)
		} else if strings.HasSuffix(cleanPath, ".makn") {
			outPath = strings.TrimSuffix(cleanPath, ".makn")
		} else {
			outPath = cleanPath + ".dec"
		}

		in, err := os.Open(cleanPath)
		if err != nil {
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			continue
		}
		fi, _ := in.Stat()
		fileBytes := fi.Size()

		if _, err := s.engine.UnprotectStream(ectx, in, nil, outPath, opts); err != nil {
			in.Close()
			_ = os.Remove(outPath)
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			continue
		}
		in.Close()

		result.Decrypted = append(result.Decrypted, RecursiveFileResult{
			Input:  path,
			Output: outPath,
			Bytes:  fileBytes,
		})
	}

	result.TotalFiles = len(result.Decrypted)
	result.Status = "success"
	if len(result.Errors) > 0 {
		result.Status = "partial"
	}
	return result, nil
}

// DecryptDirectory decrypts every *.makn file found under inputDir, writing
// output alongside each file (stripping .makn) or into outputDir when set.
// On the passphrase path each file pays its own Argon2id cost (different salts).
// Use opts.SessionKey for O(1) batch decrypt when files were encrypted together.
func (s *CryptoService) DecryptDirectory(ectx *EngineContext, inputDir, outputDir string, opts Options) (*RecursiveDecryptResult, error) {
	ectx = s.engine.context(ectx)
	if err := s.engine.enforce(ectx, CapUnprotect); err != nil {
		return nil, err
	}

	cleanDir := filepath.Clean(inputDir)
	if err := ectx.Policy.ValidatePath(cleanDir); err != nil {
		return nil, err
	}
	info, err := os.Stat(cleanDir)
	if err != nil || !info.IsDir() {
		return nil, &ErrIO{Path: inputDir, Reason: "not a directory"}
	}

	result := &RecursiveDecryptResult{}

	walkErr := filepath.WalkDir(cleanDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".makn") {
			result.Skipped = append(result.Skipped, path)
			return nil
		}

		base := filepath.Base(path)
		stripped := strings.TrimSuffix(base, ".makn")
		var outPath string
		if outputDir != "" {
			rel, _ := filepath.Rel(cleanDir, filepath.Dir(path))
			outPath = filepath.Join(filepath.Clean(outputDir), rel, stripped)
		} else {
			outPath = strings.TrimSuffix(path, ".makn")
		}

		if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			return nil
		}

		in, err := os.Open(path)
		if err != nil {
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			return nil
		}
		fi, _ := in.Stat()
		fileBytes := fi.Size()

		if _, err := s.engine.UnprotectStream(ectx, in, nil, outPath, opts); err != nil {
			in.Close()
			_ = os.Remove(outPath)
			result.Errors = append(result.Errors, RecursiveFileError{Path: path, Err: err.Error()})
			return nil
		}
		in.Close()

		result.Decrypted = append(result.Decrypted, RecursiveFileResult{
			Input: path, Output: outPath, Bytes: fileBytes,
		})
		return nil
	})

	if walkErr != nil {
		return nil, walkErr
	}
	result.TotalFiles = len(result.Decrypted)
	result.Status = "success"
	if len(result.Errors) > 0 {
		result.Status = "partial"
	}
	return result, nil
}

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

	// V2 files: ReadHeader returns placeholder profileID=0 and flags=0.
	// Read the real V2 header fields to populate the info struct accurately.
	var v2flags uint16
	var v2tlvs []TLVEntry
	if magic == MagicHeaderV2Sym || magic == MagicHeaderV2Asym {
		if err := inspectV2Fields(in, magic, &profileID, &v2flags, &recipients, &v2tlvs); err != nil {
			// Non-fatal: return partial info rather than failing entirely.
			_ = err
		}
		flags = byte(v2flags) // low byte covers Archive, Compress, Signed, Stealth
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

	switch magic {
	case MagicHeader:
		info.Type = "symmetric"
	case MagicHeaderAsym:
		info.Type = "asymmetric"
	case MagicHeaderV2Sym:
		info.Type = "symmetric"
	case MagicHeaderV2Asym:
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

	// Surface selected V2 TLV metadata in KDFDetails / SIGAlgorithm for display.
	if len(v2tlvs) > 0 {
		if fname := FindTLV(v2tlvs, TLVTagFilename); len(fname) > 0 {
			info.SIGAlgorithm = fmt.Sprintf("%s (filename: %s)", info.SIGAlgorithm, string(fname))
		}
	}

	return info, nil
}

// inspectV2Fields reads the V2 header fields that come after the magic bytes.
// in is positioned immediately after the 4-byte magic. Fields are filled into
// the pointer arguments so the caller can populate HeaderInfo without re-reading.
func inspectV2Fields(in io.Reader, magic string, profileID *byte, flags *uint16, recipientCount *byte, tlvs *[]TLVEntry) error {
	// FormatVersion (1) + ProfileID (1) + Flags (2) + RecipientCount (1, asym only) + ExtLen (2) + TLVs
	verBuf := make([]byte, 1)
	if _, err := io.ReadFull(in, verBuf); err != nil {
		return err
	}
	pidBuf := make([]byte, 1)
	if _, err := io.ReadFull(in, pidBuf); err != nil {
		return err
	}
	*profileID = pidBuf[0]
	flagsBuf := make([]byte, 2)
	if _, err := io.ReadFull(in, flagsBuf); err != nil {
		return err
	}
	*flags = binary.LittleEndian.Uint16(flagsBuf)
	if magic == MagicHeaderV2Asym {
		rcBuf := make([]byte, 1)
		if _, err := io.ReadFull(in, rcBuf); err != nil {
			return err
		}
		*recipientCount = rcBuf[0]
	}
	extLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(in, extLenBuf); err != nil {
		return err
	}
	extLen := binary.LittleEndian.Uint16(extLenBuf)
	if extLen > 0 {
		extBytes := make([]byte, extLen)
		if _, err := io.ReadFull(in, extBytes); err != nil {
			return err
		}
		*tlvs = DecodeTLVs(extBytes)
	}
	return nil
}
