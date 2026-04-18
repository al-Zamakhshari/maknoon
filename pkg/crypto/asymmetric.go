// Package crypto provides the core cryptographic primitives and streaming
// encryption logic for Maknoon.
package crypto

// GeneratePQKeyPair generates a fresh Hybrid (ML-KEM + X25519) and ML-DSA keypair using the default profile.
// The KEM keys are returned as marshaled binary for storage compatibility.
func GeneratePQKeyPair() (kemPub, kemPriv, sigPub, sigPriv []byte, err error) {
	profile := DefaultProfile()

	priv, pub, err := profile.GenerateHybridKeyPair()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	kemPriv, err = priv.Bytes()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	kemPub = pub.Bytes()

	sigPub, sigPriv, err = profile.GenerateSIGKeyPair()
	if err != nil {
		SafeClear(kemPriv)
		return nil, nil, nil, nil, err
	}

	return
}

// SignData signs a message using a Post-Quantum private key.
func SignData(message []byte, privKeyBytes []byte) ([]byte, error) {
	defer SafeClear(privKeyBytes)
	return DefaultProfile().Sign(message, privKeyBytes)
}

// VerifySignature verifies a Post-Quantum signature against a message and public key.
func VerifySignature(message []byte, signature []byte, pubKeyBytes []byte) bool {
	return DefaultProfile().Verify(message, signature, pubKeyBytes)
}
