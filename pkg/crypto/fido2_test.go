package crypto

import (
	"bytes"
	"fmt"
	"iter"
	"testing"

	"github.com/mohammadv184/go-fido2/protocol/ctap2"
	"github.com/mohammadv184/go-fido2/protocol/webauthn"
)

// MockAuthenticator implements the Authenticator interface for testing.
type MockAuthenticator struct {
	InfoFunc                      func() *ctap2.AuthenticatorGetInfoResponse
	MakeCredentialFunc            func(pinUvAuthToken []byte, clientData []byte, rp webauthn.PublicKeyCredentialRpEntity, user webauthn.PublicKeyCredentialUserEntity, pubKeyCredParams []webauthn.PublicKeyCredentialParameters, excludeList []webauthn.PublicKeyCredentialDescriptor, extInputs *webauthn.CreateAuthenticationExtensionsClientInputs, options map[ctap2.Option]bool, enterpriseAttestation uint, attestationFormatsPreference []webauthn.AttestationStatementFormatIdentifier) (*ctap2.AuthenticatorMakeCredentialResponse, error)
	GetAssertionFunc              func(pinUvAuthToken []byte, rpID string, clientData []byte, allowList []webauthn.PublicKeyCredentialDescriptor, extInputs *webauthn.GetAuthenticationExtensionsClientInputs, options map[ctap2.Option]bool) iter.Seq2[*ctap2.AuthenticatorGetAssertionResponse, error]
	GetPinUvAuthTokenUsingPINFunc func(pin string, permissions ctap2.Permission, rpID string) ([]byte, error)
	CloseFunc                     func() error
}

func (m *MockAuthenticator) Info() *ctap2.AuthenticatorGetInfoResponse {
	return m.InfoFunc()
}

func (m *MockAuthenticator) MakeCredential(pinUvAuthToken []byte, clientData []byte, rp webauthn.PublicKeyCredentialRpEntity, user webauthn.PublicKeyCredentialUserEntity, pubKeyCredParams []webauthn.PublicKeyCredentialParameters, excludeList []webauthn.PublicKeyCredentialDescriptor, extInputs *webauthn.CreateAuthenticationExtensionsClientInputs, options map[ctap2.Option]bool, enterpriseAttestation uint, attestationFormatsPreference []webauthn.AttestationStatementFormatIdentifier) (*ctap2.AuthenticatorMakeCredentialResponse, error) {
	return m.MakeCredentialFunc(pinUvAuthToken, clientData, rp, user, pubKeyCredParams, excludeList, extInputs, options, enterpriseAttestation, attestationFormatsPreference)
}

func (m *MockAuthenticator) GetAssertion(pinUvAuthToken []byte, rpID string, clientData []byte, allowList []webauthn.PublicKeyCredentialDescriptor, extInputs *webauthn.GetAuthenticationExtensionsClientInputs, options map[ctap2.Option]bool) iter.Seq2[*ctap2.AuthenticatorGetAssertionResponse, error] {
	return m.GetAssertionFunc(pinUvAuthToken, rpID, clientData, allowList, extInputs, options)
}

func (m *MockAuthenticator) GetPinUvAuthTokenUsingPIN(pin string, permissions ctap2.Permission, rpID string) ([]byte, error) {
	return m.GetPinUvAuthTokenUsingPINFunc(pin, permissions, rpID)
}

func (m *MockAuthenticator) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

func setupMock(secret, credID []byte) *MockAuthenticator {
	return &MockAuthenticator{
		InfoFunc: func() *ctap2.AuthenticatorGetInfoResponse {
			return &ctap2.AuthenticatorGetInfoResponse{
				Extensions: []webauthn.ExtensionIdentifier{"hmac-secret", "hmac-secret-mc"},
				Options:    map[ctap2.Option]bool{ctap2.OptionClientPIN: false},
			}
		},
		MakeCredentialFunc: func(_ []byte, _ []byte, _ webauthn.PublicKeyCredentialRpEntity, _ webauthn.PublicKeyCredentialUserEntity, _ []webauthn.PublicKeyCredentialParameters, _ []webauthn.PublicKeyCredentialDescriptor, _ *webauthn.CreateAuthenticationExtensionsClientInputs, _ map[ctap2.Option]bool, _ uint, _ []webauthn.AttestationStatementFormatIdentifier) (*ctap2.AuthenticatorMakeCredentialResponse, error) {
			return &ctap2.AuthenticatorMakeCredentialResponse{
				AuthData: &ctap2.MakeCredentialAuthData{
					AttestedCredentialData: &ctap2.AttestedCredentialData{
						CredentialID: credID,
					},
				},
				ExtensionOutputs: &webauthn.CreateAuthenticationExtensionsClientOutputs{
					CreateHMACSecretMCOutputs: &webauthn.CreateHMACSecretMCOutputs{
						HMACGetSecret: webauthn.HMACGetSecretOutput{
							Output1: secret,
						},
					},
				},
			}, nil
		},
		GetAssertionFunc: func(_ []byte, _ string, _ []byte, _ []webauthn.PublicKeyCredentialDescriptor, _ *webauthn.GetAuthenticationExtensionsClientInputs, _ map[ctap2.Option]bool) iter.Seq2[*ctap2.AuthenticatorGetAssertionResponse, error] {
			return func(yield func(*ctap2.AuthenticatorGetAssertionResponse, error) bool) {
				_ = yield(&ctap2.AuthenticatorGetAssertionResponse{
					ExtensionOutputs: &webauthn.GetAuthenticationExtensionsClientOutputs{
						GetHMACSecretOutputs: &webauthn.GetHMACSecretOutputs{
							HMACGetSecret: webauthn.HMACGetSecretOutput{
								Output1: secret,
							},
						},
					},
				}, nil)
			}
		},
	}
}

func TestFido2EnrollAndDeriveTopLevel(t *testing.T) {
	mockSecret := []byte("top-level-secret-32-bytes-long!!")
	mockCredID := []byte("top-level-credential-id")
	mock := setupMock(mockSecret, mockCredID)

	// Inject mock opener
	originalOpener := DefaultOpener
	defer func() { DefaultOpener = originalOpener }()
	DefaultOpener = func() (Authenticator, error) {
		return mock, nil
	}

	// Test Enroll
	meta, secret, err := Fido2Enroll("test.io", "test-user")
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	if !bytes.Equal(meta.CredentialID, mockCredID) {
		t.Errorf("CredentialID mismatch")
	}
	if !bytes.Equal(secret, mockSecret) {
		t.Errorf("Secret mismatch")
	}

	// Test Derive
	derived, err := Fido2Derive("test.io", meta.CredentialID)
	if err != nil {
		t.Fatalf("Derive failed: %v", err)
	}
	if !bytes.Equal(derived, mockSecret) {
		t.Errorf("Derived secret mismatch")
	}
}

func TestFido2OpenerError(t *testing.T) {
	originalOpener := DefaultOpener
	defer func() { DefaultOpener = originalOpener }()
	DefaultOpener = func() (Authenticator, error) {
		return nil, fmt.Errorf("device busy")
	}

	if _, _, err := Fido2Enroll("a", "b"); err == nil {
		t.Error("Expected error from opener in Enroll")
	}
	if _, err := Fido2Derive("a", []byte("b")); err == nil {
		t.Error("Expected error from opener in Derive")
	}
}

func TestFido2FallbackTouch(t *testing.T) {
	mockSecret := []byte("fallback-secret-32-bytes-long!!!")
	mockCredID := []byte("fallback-cred-id")

	mock := &MockAuthenticator{
		InfoFunc: func() *ctap2.AuthenticatorGetInfoResponse {
			return &ctap2.AuthenticatorGetInfoResponse{
				Extensions: []webauthn.ExtensionIdentifier{"hmac-secret"},
				Options:    map[ctap2.Option]bool{ctap2.OptionClientPIN: false},
			}
		},
		MakeCredentialFunc: func(_ []byte, _ []byte, _ webauthn.PublicKeyCredentialRpEntity, _ webauthn.PublicKeyCredentialUserEntity, _ []webauthn.PublicKeyCredentialParameters, _ []webauthn.PublicKeyCredentialDescriptor, _ *webauthn.CreateAuthenticationExtensionsClientInputs, _ map[ctap2.Option]bool, _ uint, _ []webauthn.AttestationStatementFormatIdentifier) (*ctap2.AuthenticatorMakeCredentialResponse, error) {
			return &ctap2.AuthenticatorMakeCredentialResponse{
				AuthData: &ctap2.MakeCredentialAuthData{
					AttestedCredentialData: &ctap2.AttestedCredentialData{
						CredentialID: mockCredID,
					},
				},
				// No ExtensionOutputs -> Force fallback
			}, nil
		},
		GetAssertionFunc: func(_ []byte, _ string, _ []byte, _ []webauthn.PublicKeyCredentialDescriptor, _ *webauthn.GetAuthenticationExtensionsClientInputs, _ map[ctap2.Option]bool) iter.Seq2[*ctap2.AuthenticatorGetAssertionResponse, error] {
			return func(yield func(*ctap2.AuthenticatorGetAssertionResponse, error) bool) {
				_ = yield(&ctap2.AuthenticatorGetAssertionResponse{
					ExtensionOutputs: &webauthn.GetAuthenticationExtensionsClientOutputs{
						GetHMACSecretOutputs: &webauthn.GetHMACSecretOutputs{
							HMACGetSecret: webauthn.HMACGetSecretOutput{
								Output1: mockSecret,
							},
						},
					},
				}, nil)
			}
		},
	}

	_, secret, err := Fido2EnrollWithAuthenticator(mock, "test.io", "user")
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	if !bytes.Equal(secret, mockSecret) {
		t.Errorf("Secret mismatch in fallback")
	}
}

func TestFido2NoAssertion(t *testing.T) {
	mock := &MockAuthenticator{
		GetAssertionFunc: func(_ []byte, _ string, _ []byte, _ []webauthn.PublicKeyCredentialDescriptor, _ *webauthn.GetAuthenticationExtensionsClientInputs, _ map[ctap2.Option]bool) iter.Seq2[*ctap2.AuthenticatorGetAssertionResponse, error] {
			return func(_ func(*ctap2.AuthenticatorGetAssertionResponse, error) bool) {
				// Yield nothing
			}
		},
	}

	_, err := fido2DeriveInternal(mock, nil, "rp", []byte("id"))
	if err == nil {
		t.Error("Expected error for no assertions")
	}
}
