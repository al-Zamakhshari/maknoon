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

func (p *ProfileV1) ID() byte { return 1 }

func (p *ProfileV1) SaltSize() int { return 32 }

func (p *ProfileV1) NonceSize() int { return 24 }

func (p *ProfileV1) DeriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, 3, 64*1024, 4, chacha20poly1305.KeySize)
}

func (p *ProfileV1) NewAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key)
}

func (p *ProfileV1) KEMName() string { return "Kyber1024" }

func (p *ProfileV1) GenerateKEMKeyPair() (pub, priv []byte, err error) {
	pk, sk, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub, _ = pk.MarshalBinary()
	priv, _ = sk.MarshalBinary()
	return pub, priv, nil
}

func (p *ProfileV1) KEMEncapsulate(pubKeyBytes []byte) (ct, ss []byte, err error) {
	scheme := kyber1024.Scheme()
	pubKey, err := scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	return scheme.Encapsulate(pubKey)
}

func (p *ProfileV1) KEMDecapsulate(privKeyBytes, ct []byte) (ss []byte, err error) {
	scheme := kyber1024.Scheme()
	privKey, err := scheme.UnmarshalBinaryPrivateKey(privKeyBytes)
	if err != nil {
		return nil, err
	}
	return scheme.Decapsulate(privKey, ct)
}

func (p *ProfileV1) KEMCiphertextSize() int {
	return kyber1024.Scheme().CiphertextSize()
}

func (p *ProfileV1) SIGName() string { return "ML-DSA-87" }

func (p *ProfileV1) GenerateSIGKeyPair() (pub, priv []byte, err error) {
	pk, sk, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub, _ = pk.MarshalBinary()
	priv, _ = sk.MarshalBinary()
	return pub, priv, nil
}

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

func (p *ProfileV1) Verify(data, sig, pubKeyBytes []byte) bool {
	pk := new(mldsa87.PublicKey)
	if err := pk.UnmarshalBinary(pubKeyBytes); err != nil {
		return false
	}
	return mldsa87.Verify(pk, data, nil, sig)
}
