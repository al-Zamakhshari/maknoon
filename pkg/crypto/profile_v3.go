package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/awnumar/memguard"
	"github.com/cloudflare/circl/kem/frodo/frodo640shake"
	"github.com/cloudflare/circl/sign/slhdsa"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func init() {
	RegisterProfile(&ProfileV3{
		ArgonTime: 3,
		ArgonMem:  64 * 1024,
		ArgonThrd: 4,
	})
}

// ProfileV3 implements the "Conservative" suite (FrodoKEM-640-SHAKE + SLH-DSA-SHA2-128s).
// This suite has NO reliance on structured lattice mathematics.
type ProfileV3 struct {
	ArgonTime uint32
	ArgonMem  uint32
	ArgonThrd uint8
}

// ID returns the profile identifier (3).
func (p *ProfileV3) ID() byte { return 3 }

// Name returns the profile name.
func (p *ProfileV3) Name() string { return "conservative" }

// SaltSize returns the salt size in bytes (32).
func (p *ProfileV3) SaltSize() int { return 32 }

// NonceSize returns the nonce size in bytes (24 for XChaCha20).
func (p *ProfileV3) NonceSize() int { return 24 }

// DeriveKey derives a symmetric key using Argon2id.
func (p *ProfileV3) DeriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, p.ArgonTime, p.ArgonMem, p.ArgonThrd, chacha20poly1305.KeySize)
}

// NewAEAD returns a new XChaCha20-Poly1305 AEAD.
func (p *ProfileV3) NewAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key)
}

// KEMName returns the KEM algorithm name.
func (p *ProfileV3) KEMName() string { return "FrodoKEM-640-SHAKE" }

// RecipientBlockSize returns the total size of an encrypted FEK block for FrodoKEM-640.
// Ciphertext: 9720 bytes. Wrapped FEK: 32 bytes. Total: 9752.
func (p *ProfileV3) RecipientBlockSize() int {
	return frodo640shake.Scheme().CiphertextSize() + 32
}

// GenerateHybridKeyPair generates a new FrodoKEM-640 key pair.
func (p *ProfileV3) GenerateHybridKeyPair() (priv, pub []byte, err error) {
	scheme := frodo640shake.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	pub, _ = pk.MarshalBinary()
	priv, _ = sk.MarshalBinary()
	return priv, pub, nil
}

// DeriveKEMPublic derives the public key from a FrodoKEM-640 private key.
func (p *ProfileV3) DeriveKEMPublic(privKeyBytes []byte) ([]byte, error) {
	scheme := frodo640shake.Scheme()
	sk, err := scheme.UnmarshalBinaryPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid KEM private key: %w", err)
	}
	return sk.Public().MarshalBinary()
}

// WrapFEK encapsulates the FEK using FrodoKEM and HKDF.
func (p *ProfileV3) WrapFEK(recipientPub []byte, flags byte, fekEnclave *memguard.Enclave) ([]byte, error) {
	scheme := frodo640shake.Scheme()
	pub, err := scheme.UnmarshalBinaryPublicKey(recipientPub)
	if err != nil {
		return nil, err
	}

	ct, ss, err := scheme.Encapsulate(pub)
	if err != nil {
		return nil, err
	}

	// Derive wrapping key from shared secret
	info := []byte{p.ID(), flags}
	hkdfReader := hkdf.New(sha256.New, ss, nil, append([]byte("maknoon-fek-wrap"), info...))
	otp := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, otp); err != nil {
		return nil, err
	}
	defer SafeClear(otp)

	fekBuf, err := fekEnclave.Open()
	if err != nil {
		return nil, err
	}
	defer fekBuf.Destroy()

	wrappedKey := make([]byte, 32)
	fekBytes := fekBuf.Bytes()
	for i := 0; i < 32; i++ {
		wrappedKey[i] = fekBytes[i] ^ otp[i]
	}

	result := make([]byte, 0, len(ct)+len(wrappedKey))
	result = append(result, ct...)
	result = append(result, wrappedKey...)
	return result, nil
}

// UnwrapFEK decapsulates the FEK using FrodoKEM and HKDF.
func (p *ProfileV3) UnwrapFEK(recipientPriv []byte, flags byte, headerData []byte) (*memguard.Enclave, error) {
	scheme := frodo640shake.Scheme()
	ctSize := scheme.CiphertextSize()
	if len(headerData) < ctSize+32 {
		return nil, fmt.Errorf("invalid header data length")
	}

	ct := headerData[:ctSize]
	wrappedKey := headerData[ctSize : ctSize+32]

	priv, err := scheme.UnmarshalBinaryPrivateKey(recipientPriv)
	if err != nil {
		return nil, err
	}

	ss, err := scheme.Decapsulate(priv, ct)
	if err != nil {
		return nil, err
	}

	// Derive wrapping key
	info := []byte{p.ID(), flags}
	hkdfReader := hkdf.New(sha256.New, ss, nil, append([]byte("maknoon-fek-wrap"), info...))
	otp := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, otp); err != nil {
		return nil, err
	}
	defer SafeClear(otp)

	fekBuf := memguard.NewBuffer(32)
	fekBytes := fekBuf.Bytes()
	for i := 0; i < 32; i++ {
		fekBytes[i] = wrappedKey[i] ^ otp[i]
	}

	return fekBuf.Seal(), nil
}

// SIGName returns the signature algorithm name.
func (p *ProfileV3) SIGName() string { return "SLH-DSA-SHA2-128s" }

// SIGSize returns the size of the signature in bytes.
func (p *ProfileV3) SIGSize() int {
	return slhdsa.SHA2_128s.Scheme().SignatureSize()
}

// GenerateSIGKeyPair generates a new SLH-DSA-SHA2-128s keypair.
func (p *ProfileV3) GenerateSIGKeyPair() (pub, priv []byte, err error) {
	pk, sk, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	if err != nil {
		return nil, nil, err
	}
	pub, _ = pk.MarshalBinary()
	priv, _ = sk.MarshalBinary()
	return pub, priv, nil
}

// Sign signs the data using the SLH-DSA-SHA2-128s private key.
func (p *ProfileV3) Sign(data, privKeyBytes []byte) ([]byte, error) {
	scheme := slhdsa.SHA2_128s.Scheme()
	sk, err := scheme.UnmarshalBinaryPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid signing key: %w", err)
	}

	return scheme.Sign(sk, data, nil), nil
}

// Verify verifies the SLH-DSA-SHA2-128s signature.
func (p *ProfileV3) Verify(data, sig, pubKeyBytes []byte) bool {
	scheme := slhdsa.SHA2_128s.Scheme()
	pk, err := scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return false
	}
	return scheme.Verify(pk, data, sig, nil)
}
