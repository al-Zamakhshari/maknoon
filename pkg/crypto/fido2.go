package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"iter"
	"os"

	"github.com/mohammadv184/go-fido2"
	"github.com/mohammadv184/go-fido2/protocol/ctap2"
	"github.com/mohammadv184/go-fido2/protocol/webauthn"
	"golang.org/x/term"
)

// Authenticator defines the interface for interacting with a FIDO2 security key.
// This allows us to mock the hardware for testing.
type Authenticator interface {
	Info() *ctap2.AuthenticatorGetInfoResponse
	MakeCredential(pinUvAuthToken []byte, clientData []byte, rp webauthn.PublicKeyCredentialRpEntity, user webauthn.PublicKeyCredentialUserEntity, pubKeyCredParams []webauthn.PublicKeyCredentialParameters, excludeList []webauthn.PublicKeyCredentialDescriptor, extInputs *webauthn.CreateAuthenticationExtensionsClientInputs, options map[ctap2.Option]bool, enterpriseAttestation uint, attestationFormatsPreference []webauthn.AttestationStatementFormatIdentifier) (*ctap2.AuthenticatorMakeCredentialResponse, error)
	GetAssertion(pinUvAuthToken []byte, rpID string, clientData []byte, allowList []webauthn.PublicKeyCredentialDescriptor, extInputs *webauthn.GetAuthenticationExtensionsClientInputs, options map[ctap2.Option]bool) iter.Seq2[*ctap2.AuthenticatorGetAssertionResponse, error]
	GetPinUvAuthTokenUsingPIN(pin string, permissions ctap2.Permission, rpID string) ([]byte, error)
	Close() error
}

// AuthenticatorOpener is a function that opens a FIDO2 device.
type AuthenticatorOpener func() (Authenticator, error)

// DefaultOpener is the default implementation that opens the first physical FIDO2 device found.
var DefaultOpener AuthenticatorOpener = func() (Authenticator, error) {
	descriptors, err := fido2.Enumerate()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate FIDO2 devices: %w", err)
	}
	if len(descriptors) == 0 {
		return nil, fmt.Errorf("no FIDO2 security keys found. Please plug in your key")
	}

	dev, err := fido2.Open(descriptors[0])
	if err != nil {
		return nil, fmt.Errorf("failed to open FIDO2 device: %w", err)
	}
	return dev, nil
}

// Fido2Metadata stores the information needed to re-authenticate with a FIDO2 key.
type Fido2Metadata struct {
	CredentialID []byte `json:"credential_id"`
	RPID         string `json:"rp_id"`
}

var fido2Salt = sha256.Sum256([]byte("maknoon-fido2-hmac-salt"))

// Fido2Enroll registers a new FIDO2 credential with hmac-secret support.
func Fido2Enroll(rpID, user string) (*Fido2Metadata, []byte, error) {
	dev, err := DefaultOpener()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = dev.Close() }()

	return Fido2EnrollWithAuthenticator(dev, rpID, user)
}

// Fido2EnrollWithAuthenticator is the internal enrollment logic that takes an Authenticator interface.
func Fido2EnrollWithAuthenticator(dev Authenticator, rpID, user string) (*Fido2Metadata, []byte, error) {
	info := dev.Info()
	if !hasHMACSecretSupport(info) {
		return nil, nil, fmt.Errorf("your security key does not support the 'hmac-secret' extension")
	}

	token, err := handleFido2PIN(dev, info, rpID)
	if err != nil {
		return nil, nil, err
	}

	fmt.Println("Please touch your security key to register...")
	res, err := registerFido2Credential(dev, token, rpID, user, hasHMACSecretMC(info))
	if err != nil {
		return nil, nil, err
	}

	if res.AuthData == nil || res.AuthData.AttestedCredentialData == nil {
		return nil, nil, fmt.Errorf("FIDO2 key did not return attested credential data")
	}
	credentialID := res.AuthData.AttestedCredentialData.CredentialID

	initialSecret, err := extractOrDeriveSecret(dev, res, token, rpID, credentialID)
	if err != nil {
		return nil, nil, err
	}

	return &Fido2Metadata{
		CredentialID: credentialID,
		RPID:         rpID,
	}, initialSecret, nil
}

func hasHMACSecretSupport(info *ctap2.AuthenticatorGetInfoResponse) bool {
	for _, ext := range info.Extensions {
		if ext == "hmac-secret" {
			return true
		}
	}
	return false
}

func hasHMACSecretMC(info *ctap2.AuthenticatorGetInfoResponse) bool {
	for _, ext := range info.Extensions {
		if ext == "hmac-secret-mc" {
			return true
		}
	}
	return false
}

func handleFido2PIN(dev Authenticator, info *ctap2.AuthenticatorGetInfoResponse, rpID string) ([]byte, error) {
	if info.Options[ctap2.OptionClientPIN] {
		fmt.Print("Enter FIDO2 Security Key PIN: ")
		pin, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, err
		}
		defer SafeClear(pin)
		token, err := dev.GetPinUvAuthTokenUsingPIN(string(pin), ctap2.PermissionMakeCredential|ctap2.PermissionGetAssertion, rpID)
		if err != nil {
			return nil, fmt.Errorf("PIN authentication failed: %w", err)
		}
		return token, nil
	}
	return nil, nil
}

func registerFido2Credential(dev Authenticator, token []byte, rpID, user string, hmacMC bool) (*ctap2.AuthenticatorMakeCredentialResponse, error) {
	clientDataHash := make([]byte, 32)
	if _, err := rand.Read(clientDataHash); err != nil {
		return nil, err
	}

	extInputs := &webauthn.CreateAuthenticationExtensionsClientInputs{
		CreateHMACSecretInputs: &webauthn.CreateHMACSecretInputs{HMACCreateSecret: true},
	}
	if hmacMC {
		extInputs.CreateHMACSecretMCInputs = &webauthn.CreateHMACSecretMCInputs{
			HMACGetSecret: webauthn.HMACGetSecretInput{
				Salt1: fido2Salt[:],
			},
		}
	}

	return dev.MakeCredential(
		token,
		clientDataHash,
		webauthn.PublicKeyCredentialRpEntity{ID: rpID, Name: "Maknoon CLI"},
		webauthn.PublicKeyCredentialUserEntity{ID: []byte(user), Name: user, DisplayName: user},
		[]webauthn.PublicKeyCredentialParameters{
			{Type: webauthn.PublicKeyCredentialTypePublicKey, Algorithm: -7},
		},
		nil,
		extInputs,
		nil,
		0,
		nil,
	)
}

func extractOrDeriveSecret(dev Authenticator, res *ctap2.AuthenticatorMakeCredentialResponse, token []byte, rpID string, credentialID []byte) ([]byte, error) {
	var initialSecret []byte
	if res.ExtensionOutputs != nil && len(res.ExtensionOutputs.HMACGetSecret.Output1) > 0 {
		initialSecret = res.ExtensionOutputs.HMACGetSecret.Output1
	}

	if len(initialSecret) == 0 {
		fmt.Println("One more touch needed to initialize hardware secret...")
		return fido2DeriveInternal(dev, token, rpID, credentialID)
	}
	return initialSecret, nil
}

// Fido2Derive derives a deterministic 256-bit key from a FIDO2 key.
func Fido2Derive(rpID string, credentialID []byte) ([]byte, error) {
	dev, err := DefaultOpener()
	if err != nil {
		return nil, err
	}
	defer func() { _ = dev.Close() }()

	return Fido2DeriveWithAuthenticator(dev, rpID, credentialID)
}

// Fido2DeriveWithAuthenticator is the internal derivation logic that takes an Authenticator interface.
func Fido2DeriveWithAuthenticator(dev Authenticator, rpID string, credentialID []byte) ([]byte, error) {
	info := dev.Info()
	var token []byte
	if info.Options[ctap2.OptionClientPIN] {
		fmt.Print("Enter FIDO2 Security Key PIN: ")
		pin, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, err
		}
		defer SafeClear(pin)
		var err2 error
		token, err2 = dev.GetPinUvAuthTokenUsingPIN(string(pin), ctap2.PermissionGetAssertion, rpID)
		if err2 != nil {
			return nil, fmt.Errorf("PIN authentication failed: %w", err2)
		}
	}

	return fido2DeriveInternal(dev, token, rpID, credentialID)
}

func fido2DeriveInternal(dev Authenticator, token []byte, rpID string, credentialID []byte) ([]byte, error) {
	fmt.Println("Please touch your security key to derive the key...")

	clientDataHash := make([]byte, 32)
	if _, err := rand.Read(clientDataHash); err != nil {
		return nil, err
	}

	assertions := dev.GetAssertion(
		token,
		rpID,
		clientDataHash,
		[]webauthn.PublicKeyCredentialDescriptor{
			{Type: webauthn.PublicKeyCredentialTypePublicKey, ID: credentialID},
		},
		&webauthn.GetAuthenticationExtensionsClientInputs{
			GetHMACSecretInputs: &webauthn.GetHMACSecretInputs{
				HMACGetSecret: webauthn.HMACGetSecretInput{
					Salt1: fido2Salt[:],
				},
			},
		},
		nil,
	)

	for res, err := range assertions {
		if err != nil {
			return nil, fmt.Errorf("failed to get FIDO2 assertion: %w", err)
		}

		if res.ExtensionOutputs == nil || len(res.ExtensionOutputs.HMACGetSecret.Output1) == 0 {
			return nil, fmt.Errorf("FIDO2 key did not return an hmac-secret extension output")
		}

		return res.ExtensionOutputs.HMACGetSecret.Output1, nil
	}

	return nil, fmt.Errorf("no assertion returned from FIDO2 key")
}
