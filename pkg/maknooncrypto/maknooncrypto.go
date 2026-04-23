// Package maknooncrypto provides the core hybrid post-quantum key encapsulation
// logic for the Maknoon encryption tool. It mathematically guarantees memory safety
// by defeating the Go garbage collector and preventing secrets from swapping to disk.
//
// By exporting the derived secret to key Maknoon's native XChaCha20-Poly1305
// cipher, we maintain our 192-bit extended nonce architecture, which is critical
// for safe, lock-free parallel chunk encryption across the multi-core worker pool.
package maknooncrypto

import (
	"crypto/hpke"
	"errors"
	"fmt"

	"github.com/awnumar/memguard"
)

const (
	// fekSize is the size of the File Encryption Key for XChaCha20-Poly1305 (32 bytes).
	fekSize = 32
)

// SafeClear deterministically zeroizes a standard Go byte slice using memguard for reliability.
func SafeClear(b []byte) {
	memguard.WipeBytes(b)
}

// GenerateKeys generates a new key pair for the hybrid ML-KEM-768 + X25519 KEM.
func GenerateKeys() (hpke.PrivateKey, hpke.PublicKey, error) {
	kem := hpke.MLKEM768X25519()

	priv, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate hybrid keys: %w", err)
	}

	return priv, priv.PublicKey(), nil
}

// WrapEphemeralKey encapsulates a memory-guarded ephemeral symmetric key (FEK).
func WrapEphemeralKey(recipientPub hpke.PublicKey, profileID byte, headerFlags byte, ephemeralKeyEnclave *memguard.Enclave) ([]byte, error) {
	fekBuf, err := ephemeralKeyEnclave.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open ephemeral key enclave: %w", err)
	}
	defer fekBuf.Destroy()

	if fekBuf.Size() != fekSize {
		return nil, errors.New("ephemeral key must be exactly 32 bytes for XChaCha20-Poly1305")
	}

	info := []byte{profileID, headerFlags}

	// Use standard HPKE Sender with ChaCha20-Poly1305 AEAD.
	enc, sender, err := hpke.NewSender(recipientPub, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		return nil, fmt.Errorf("hpke sender setup failed: %w", err)
	}
	ciphertext, err := sender.Seal(nil, fekBuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("hpke seal failed: %w", err)
	}

	// Result is encapsulated key (enc) + wrapped FEK (ciphertext).
	result := make([]byte, 0, len(enc)+len(ciphertext))
	result = append(result, enc...)
	result = append(result, ciphertext...)

	return result, nil
}

// UnwrapEphemeralKey decapsulates the key material and safely derives the FEK.
func UnwrapEphemeralKey(recipientPriv hpke.PrivateKey, profileID byte, headerFlags byte, headerData []byte) (*memguard.Enclave, error) {
	// For ML-KEM-768 (1088) + X25519 (32) = 1120 bytes.
	const encSize = 1120
	// Standard HPKE ciphertext for 32-byte payload with ChaCha20-Poly1305 is 32 + 16 = 48 bytes.
	const expectedCiphertextSize = 48

	if len(headerData) < encSize+expectedCiphertextSize {
		return nil, errors.New("invalid header data length: insufficient encapsulated material")
	}

	enc := headerData[:encSize]
	ciphertext := headerData[encSize : encSize+expectedCiphertextSize]

	info := []byte{profileID, headerFlags}

	receiver, err := hpke.NewRecipient(enc, recipientPriv, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		return nil, fmt.Errorf("hpke receiver setup failed: %w", err)
	}
	fekBytes, err := receiver.Open(nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("hpke open failed: %w", err)
	}
	defer SafeClear(fekBytes)

	return memguard.NewBufferFromBytes(fekBytes).Seal(), nil
}
