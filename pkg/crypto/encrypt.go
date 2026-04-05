package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptStream symmetrically encrypts data from r to w using a passphrase.
func EncryptStream(r io.Reader, w io.Writer, password []byte, flags byte) error {
	// 1. Generate random Salt for Argon2id
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	// 2. Derive Key: Argon2id (Time: 3, Mem: 64MB, Threads: 4)
	key := argon2.IDKey(password, salt, 3, 64*1024, 4, chacha20poly1305.KeySize)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// 3. Setup XChaCha20-Poly1305 & Random Base Nonce
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return err
	}

	// 4. Write Header: Magic (4) | Version (1) | Flags (1) | Salt (32) | BaseNonce (24)
	if _, err := w.Write([]byte(MagicHeader)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{Version, flags}); err != nil {
		return err
	}
	if _, err := w.Write(salt); err != nil {
		return err
	}
	if _, err := w.Write(baseNonce); err != nil {
		return err
	}

	// 5. Stream Encrypt Chunks
	return streamEncrypt(r, w, aead, baseNonce)
}

// EncryptStreamWithPublicKey encrypts data from r to w using a Post-Quantum Public Key (Kyber1024).
func EncryptStreamWithPublicKey(r io.Reader, w io.Writer, pubKeyBytes []byte, flags byte) error {
	// 1. Unpack Public Key
	scheme := kyber1024.Scheme()
	pubKey, err := scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// 2. Encapsulate Shared Secret
	ct, ss, err := scheme.Encapsulate(pubKey)
	if err != nil {
		return fmt.Errorf("failed to encapsulate: %w", err)
	}
	defer func() {
		for i := range ss {
			ss[i] = 0
		}
	}()

	// 3. Setup AEAD with Shared Secret (32 bytes)
	aead, err := chacha20poly1305.NewX(ss)
	if err != nil {
		return err
	}
	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return err
	}

	// 4. Write Header: Magic (4) | Version (1) | Flags (1) | KEM Ciphertext (1568) | BaseNonce (24)
	if _, err := w.Write([]byte(MagicHeaderAsym)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{Version, flags}); err != nil {
		return err
	}
	if _, err := w.Write(ct); err != nil {
		return err
	}
	if _, err := w.Write(baseNonce); err != nil {
		return err
	}

	// 5. Stream Encrypt Chunks
	return streamEncrypt(r, w, aead, baseNonce)
}

// Internal helper to avoid code duplication
func streamEncrypt(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte) error {
	buf := make([]byte, ChunkSize)
	chunkIndex := uint64(0)
	nonce := make([]byte, aead.NonceSize())

	for {
		n, err := r.Read(buf)
		if n > 0 {
			copy(nonce, baseNonce)
			counterBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(counterBytes, chunkIndex)
			for i := 0; i < 8; i++ {
				nonce[16+i] ^= counterBytes[i]
			}

			ciphertext := aead.Seal(nil, nonce, buf[:n], nil)

			lenBuf := make([]byte, 4)
			binary.LittleEndian.PutUint32(lenBuf, uint32(len(ciphertext)))
			if _, wErr := w.Write(lenBuf); wErr != nil {
				return wErr
			}
			if _, wErr := w.Write(ciphertext); wErr != nil {
				return wErr
			}
			chunkIndex++
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}
