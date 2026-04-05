package crypto

import (
	"crypto/rand"
	
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

// GeneratePQKeyPair generates a Post-Quantum Kyber1024 keypair for future hybrid encryption modes.
func GeneratePQKeyPair() ([]byte, []byte, error) {
	pk, sk, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	
	return pkBytes, skBytes, nil
}
