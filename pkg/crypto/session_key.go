package crypto

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
)

// DeriveSessionKey derives a 32-byte session key from a passphrase using the default profile.
// Call once and pass the returned key to EncryptStreamWithKey for many files.
// The caller must store salt alongside the key to enable decryption later.
func DeriveSessionKey(password []byte) (key []byte, salt []byte, err error) {
	profile := DefaultProfile()
	salt = make([]byte, profile.SaltSize())
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, fmt.Errorf("session key: failed to generate salt: %w", err)
	}
	key = profile.DeriveKey(password, salt)
	return key, salt, nil
}

// RederiveSessionKey reconstructs a session key from a passphrase and its stored salt.
func RederiveSessionKey(password, salt []byte) ([]byte, error) {
	profile := DefaultProfile()
	if len(salt) != profile.SaltSize() {
		return nil, fmt.Errorf("session key: salt length %d does not match profile expectation %d", len(salt), profile.SaltSize())
	}
	return profile.DeriveKey(password, salt), nil
}

// EncryptStreamWithKey encrypts using a pre-derived 32-byte key, bypassing KDF.
// The salt parameter is written into the header so the stream is self-describing
// (the same salt was used to derive this key; decryption needs it for re-derivation
// only if the caller uses RederiveSessionKey — not needed for EncryptStreamWithKey/
// DecryptStreamWithKey which take the raw key directly).
// Flags and profileID follow the same conventions as EncryptStream.
func EncryptStreamWithKey(r io.Reader, w io.Writer, key []byte, salt []byte, flags byte, concurrency int, profileID byte) error {
	profile := DefaultProfile()
	if profileID != 0 {
		var err error
		profile, err = GetProfile(profileID, nil)
		if err != nil {
			return &ErrFormat{Reason: fmt.Sprintf("EncryptStreamWithKey: unknown profile %d: %v", profileID, err)}
		}
	}

	if len(key) != 32 {
		return &ErrFormat{Reason: fmt.Sprintf("EncryptStreamWithKey: key must be 32 bytes, got %d", len(key))}
	}

	// Pad or truncate salt to profile expectation (allows caller to pass zero salt for ephemeral use)
	paddedSalt := make([]byte, profile.SaltSize())
	if len(salt) > 0 {
		copy(paddedSalt, salt)
	}

	aead, err := profile.NewAEAD(key)
	if err != nil {
		return &ErrCrypto{Reason: fmt.Sprintf("EncryptStreamWithKey: AEAD init: %v", err)}
	}
	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return &ErrIO{Path: "stream", Reason: fmt.Sprintf("EncryptStreamWithKey: base nonce: %v", err)}
	}

	if flags&FlagStealth == 0 {
		if _, err := w.Write([]byte(MagicHeader)); err != nil {
			return &ErrIO{Path: "output", Reason: err.Error()}
		}
	}
	if _, err := w.Write([]byte{profile.ID(), flags}); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}
	if _, err := w.Write(paddedSalt); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}
	if _, err := w.Write(baseNonce); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}

	ectx := defaultEngineContext()
	return streamEncrypt(r, w, aead, baseNonce, concurrency, ectx)
}

// DecryptStreamWithKey decrypts a stream that was encrypted with EncryptStreamWithKey,
// using the same pre-derived key. The salt embedded in the header is read but ignored
// (the key itself carries all key material).
func DecryptStreamWithKey(r io.Reader, w io.Writer, key []byte, concurrency int, stealth bool) (profileID byte, flags byte, err error) {
	if w == nil {
		w = io.Discard
	}

	_, profileID, flags, _, err = ReadHeader(r, stealth)
	if err != nil {
		return 0, 0, err
	}

	profile, err := GetProfile(profileID, nil)
	if err != nil {
		return 0, 0, &ErrFormat{Reason: fmt.Sprintf("DecryptStreamWithKey: unknown profile %d: %v", profileID, err)}
	}

	// Read (and discard) salt — it was stored only for self-description
	salt := make([]byte, profile.SaltSize())
	if _, err := io.ReadFull(r, salt); err != nil {
		return 0, 0, &ErrIO{Path: "input", Reason: "DecryptStreamWithKey: failed to read salt"}
	}
	_ = salt

	aead, err := profile.NewAEAD(key)
	if err != nil {
		return 0, 0, &ErrCrypto{Reason: fmt.Sprintf("DecryptStreamWithKey: AEAD init: %v", err)}
	}

	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return 0, 0, &ErrIO{Path: "input", Reason: "DecryptStreamWithKey: failed to read base nonce"}
	}

	ectx := defaultEngineContext()
	err = streamDecrypt(r, w, aead, baseNonce, concurrency, ectx)
	return profileID, flags, err
}

func defaultEngineContext() *EngineContext {
	return &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
}
