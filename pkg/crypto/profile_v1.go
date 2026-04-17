package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

func init() {
	RegisterProfile(&ProfileV1{})
}

// ProfileV1 implements the standard NIST PQC suite (Maknoon v1).
type ProfileV1 struct{}

// ID returns the profile identifier (1).
func (p *ProfileV1) ID() byte { return 1 }

// SaltSize returns the salt size in bytes (32).
func (p *ProfileV1) SaltSize() int { return 32 }

// NonceSize returns the nonce size in bytes (24 for XChaCha20).
func (p *ProfileV1) NonceSize() int { return 24 }

// DeriveKey derives a symmetric key using Argon2id.
func (p *ProfileV1) DeriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, 3, 64*1024, 4, chacha20poly1305.KeySize)
}

// NewAEAD returns a new XChaCha20-Poly1305 AEAD.
func (p *ProfileV1) NewAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key)
}

// KEMName returns the KEM algorithm name.
func (p *ProfileV1) KEMName() string { return "Kyber1024" }

// GenerateKEMKeyPair generates a new Kyber1024 keypair.
func (p *ProfileV1) GenerateKEMKeyPair() (pub, priv []byte, err error) {
	pk, sk, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub, _ = pk.MarshalBinary()
	priv, _ = sk.MarshalBinary()
	return pub, priv, nil
}

// KEMEncapsulate generates a shared secret and ciphertext for a public key.
func (p *ProfileV1) KEMEncapsulate(pubKeyBytes []byte) (ct, ss []byte, err error) {
	scheme := kyber1024.Scheme()
	pubKey, err := scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	return scheme.Encapsulate(pubKey)
}

// KEMDecapsulate derives the shared secret from a ciphertext and private key.
func (p *ProfileV1) KEMDecapsulate(privKeyBytes, ct []byte) (ss []byte, err error) {
	scheme := kyber1024.Scheme()
	privKey, err := scheme.UnmarshalBinaryPrivateKey(privKeyBytes)
	if err != nil {
		return nil, err
	}
	return scheme.Decapsulate(privKey, ct)
}

// KEMCiphertextSize returns the size of the KEM ciphertext.
func (p *ProfileV1) KEMCiphertextSize() int {
	return kyber1024.Scheme().CiphertextSize()
}

// SIGName returns the signature algorithm name.
func (p *ProfileV1) SIGName() string { return "ML-DSA-87" }

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
