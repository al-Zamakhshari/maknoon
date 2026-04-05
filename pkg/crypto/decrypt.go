package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// DecryptStream decrypts data from r to w using a passphrase.
func DecryptStream(r io.Reader, w io.Writer, password []byte) (byte, error) {
	// 1. Read Header
	header := make([]byte, 4+1+1+SaltSize+24)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, err
	}

	if string(header[:4]) != MagicHeader {
		return 0, errors.New("invalid file format: missing MAKN magic header")
	}
	if header[4] != Version {
		return 0, errors.New("unsupported maknoon version")
	}
	flags := header[5]

	salt := header[6 : 6+SaltSize]
	baseNonce := header[6+SaltSize:]

	// 2. Derive Key
	key := argon2.IDKey(password, salt, 3, 64*1024, 4, chacha20poly1305.KeySize)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// 3. Setup AEAD
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return 0, err
	}

	// 4. Stream Decrypt Chunks
	return flags, streamDecrypt(r, w, aead, baseNonce)
}

// DecryptStreamWithPrivateKey decrypts data from r to w using a Post-Quantum Private Key (Kyber1024).
func DecryptStreamWithPrivateKey(r io.Reader, w io.Writer, privKeyBytes []byte) (byte, error) {
	// 1. Read Header (Fixed part)
	fixedHeader := make([]byte, 4+1+1)
	if _, err := io.ReadFull(r, fixedHeader); err != nil {
		return 0, err
	}

	if string(fixedHeader[:4]) != MagicHeaderAsym {
		return 0, errors.New("invalid file format: missing MAKA magic header")
	}
	if fixedHeader[4] != Version {
		return 0, errors.New("unsupported maknoon version")
	}
	flags := fixedHeader[5]

	// 2. Read KEM Ciphertext
	scheme := kyber1024.Scheme()
	ct := make([]byte, scheme.CiphertextSize())
	if _, err := io.ReadFull(r, ct); err != nil {
		return 0, err
	}

	// 3. Read Base Nonce
	baseNonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return 0, err
	}

	// 4. Decapsulate Shared Secret
	privKey, err := scheme.UnmarshalBinaryPrivateKey(privKeyBytes)
	if err != nil {
		return 0, fmt.Errorf("invalid private key: %w", err)
	}
	ss, err := scheme.Decapsulate(privKey, ct)
	if err != nil {
		return 0, fmt.Errorf("decapsulation failed: %w", err)
	}
	defer func() {
		for i := range ss {
			ss[i] = 0
		}
	}()

	// 5. Setup AEAD
	aead, err := chacha20poly1305.NewX(ss)
	if err != nil {
		return 0, err
	}

	// 6. Stream Decrypt Chunks
	return flags, streamDecrypt(r, w, aead, baseNonce)
}

func streamDecrypt(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte) error {
	chunkIndex := uint64(0)
	nonce := make([]byte, aead.NonceSize())
	lenBuf := make([]byte, 4)

	for {
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		chunkLen := binary.LittleEndian.Uint32(lenBuf)
		if chunkLen > uint32(ChunkSize+16) {
			return errors.New("corrupted payload: chunk size exceeds maximum")
		}

		ciphertext := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, ciphertext); err != nil {
			return err
		}

		copy(nonce, baseNonce)
		counterBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(counterBytes, chunkIndex)
		for i := 0; i < 8; i++ {
			nonce[16+i] ^= counterBytes[i]
		}

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return errors.New("authentication failed: incorrect key or corrupted data")
		}

		if _, err := w.Write(plaintext); err != nil {
			return err
		}
		chunkIndex++
	}
	return nil
}
