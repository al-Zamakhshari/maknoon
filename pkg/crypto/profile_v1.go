package crypto

import (
	"crypto/cipher"
	"crypto/hpke"
	"crypto/rand"
	"fmt"

	"github.com/al-Zamakhshari/maknoon/pkg/maknooncrypto"
	"github.com/awnumar/memguard"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

func init() {
	RegisterProfile(&ProfileV1{
		ArgonTime: 3,
		ArgonMem:  64 * 1024,
		ArgonThrd: 4,
	})
}

// ProfileV1 implements the standard NIST PQC suite (Maknoon v2 Hybrid).
type ProfileV1 struct {
	ArgonTime uint32
	ArgonMem  uint32
	ArgonThrd uint8
}

// ID returns the profile identifier (1).
func (p *ProfileV1) ID() byte { return 1 }

// SaltSize returns the salt size in bytes (32).
func (p *ProfileV1) SaltSize() int { return 32 }

// NonceSize returns the nonce size in bytes (24 for XChaCha20).
func (p *ProfileV1) NonceSize() int { return 24 }

// DeriveKey derives a symmetric key using Argon2id.
func (p *ProfileV1) DeriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, p.ArgonTime, p.ArgonMem, p.ArgonThrd, chacha20poly1305.KeySize)
}

// NewAEAD returns a new XChaCha20-Poly1305 AEAD.
func (p *ProfileV1) NewAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key)
}

// KEMName returns the KEM algorithm name.
func (p *ProfileV1) KEMName() string { return "Hybrid ML-KEM-768+X25519" }

// RecipientBlockSize returns the total size of an encrypted FEK block (1120 + 48 = 1168).
func (p *ProfileV1) RecipientBlockSize() int { return 1168 }

// GenerateHybridKeyPair generates a new hybrid key pair (ML-KEM-768 + X25519).
func (p *ProfileV1) GenerateHybridKeyPair() (priv, pub []byte, err error) {
	sk, pk, err := maknooncrypto.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}
	priv, err = sk.Bytes()
	if err != nil {
		return nil, nil, err
	}
	pub = pk.Bytes()
	return priv, pub, nil
}

// DeriveKEMPublic derives the public key from a Hybrid KEM private key.
func (p *ProfileV1) DeriveKEMPublic(privKeyBytes []byte) ([]byte, error) {
	kem := hpke.MLKEM768X25519()
	sk, err := kem.NewPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid KEM private key: %w", err)
	}
	return sk.PublicKey().Bytes(), nil
}

// WrapFEK encapsulates the FEK using HPKE.
func (p *ProfileV1) WrapFEK(recipientPub []byte, flags byte, fekEnclave *memguard.Enclave) ([]byte, error) {
	kem := hpke.MLKEM768X25519()
	pk, err := kem.NewPublicKey(recipientPub)
	if err != nil {
		return nil, err
	}
	return maknooncrypto.WrapEphemeralKey(pk, p.ID(), flags, fekEnclave)
}

// UnwrapFEK decapsulates the FEK using HPKE.
func (p *ProfileV1) UnwrapFEK(recipientPriv []byte, flags byte, headerData []byte) (*memguard.Enclave, error) {
	kem := hpke.MLKEM768X25519()
	sk, err := kem.NewPrivateKey(recipientPriv)
	if err != nil {
		return nil, err
	}
	return maknooncrypto.UnwrapEphemeralKey(sk, p.ID(), flags, headerData)
}

// SIGName returns the signature algorithm name.
func (p *ProfileV1) SIGName() string { return "ML-DSA-87" }

// SIGSize returns the size of the signature in bytes.
func (p *ProfileV1) SIGSize() int { return mldsa87.SignatureSize }

// GenerateSIGKeyPair generates a new ML-DSA-87 keypair.
func (p *ProfileV1) GenerateSIGKeyPair() (pub, priv []byte, err error) {
	pk, sk, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub, _ = pk.MarshalBinary()
	priv, _ = sk.MarshalBinary()
	return pub, priv, nil
}

// Sign signs the data using the ML-DSA-87 private key.
func (p *ProfileV1) Sign(data, privKeyBytes []byte) ([]byte, error) {
	sk := new(mldsa87.PrivateKey)
	if err := sk.UnmarshalBinary(privKeyBytes); err != nil {
		return nil, fmt.Errorf("invalid signing key: %w", err)
	}

	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(sk, data, nil, true, sig); err != nil {
		return nil, fmt.Errorf("signing failure: %w", err)
	}
	return sig, nil
}

// Verify verifies the ML-DSA-87 signature for the given data and public key.
func (p *ProfileV1) Verify(data, sig, pubKeyBytes []byte) bool {
	pk := new(mldsa87.PublicKey)
	if err := pk.UnmarshalBinary(pubKeyBytes); err != nil {
		return false
	}
	return mldsa87.Verify(pk, data, nil, sig)
}
