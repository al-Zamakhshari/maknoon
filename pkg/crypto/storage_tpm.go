package crypto

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// TPMKeyStore is a hardware-hardened KeyStore that uses a TPM 2.0 device
// to protect sensitive cryptographic material.
type TPMKeyStore struct {
	base    KeyStore
	tpmPath string
	pcrs    []int
}

// NewTPMKeyStore creates a new TPM-backed KeyStore.
// tpmPath is typically "/dev/tpmrm0" on Linux.
func NewTPMKeyStore(base KeyStore, tpmPath string, pcrs []int) *TPMKeyStore {
	if tpmPath == "" {
		tpmPath = "/dev/tpmrm0"
	}
	return &TPMKeyStore{
		base:    base,
		tpmPath: tpmPath,
		pcrs:    pcrs,
	}
}

func (s *TPMKeyStore) ReadKey(path string) ([]byte, error) {
	data, err := s.base.ReadKey(path)
	if err != nil {
		return nil, err
	}

	// For Phase 8, we attempt to unseal if the data looks like a TPM blob.
	unwrapped, err := s.unseal(data)
	if err != nil {
		// Fallback to raw read for non-wrapped keys (migration support)
		return data, nil
	}
	return unwrapped, nil
}

func (s *TPMKeyStore) WriteKey(path string, data []byte, perm uint32) error {
	wrapped, err := s.seal(data)
	if err != nil {
		return fmt.Errorf("TPM seal failed: %w", err)
	}
	return s.base.WriteKey(path, wrapped, perm)
}

func (s *TPMKeyStore) Exists(path string) bool               { return s.base.Exists(path) }
func (s *TPMKeyStore) ListKeys(dir string) ([]string, error) { return s.base.ListKeys(dir) }
func (s *TPMKeyStore) EnsureDir(dir string) error            { return s.base.EnsureDir(dir) }
func (s *TPMKeyStore) ResolvePath(name string) (string, error) {
	return s.base.ResolvePath(name)
}
func (s *TPMKeyStore) GetBaseDir() string { return s.base.GetBaseDir() }

func (s *TPMKeyStore) seal(data []byte) ([]byte, error) {
	tpm, err := linuxtpm.Open(s.tpmPath)
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	// 1. Create a Primary Key (Storage Root Key)
	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext{FlushHandle: primary.ObjectHandle}.Execute(tpm)

	var authPolicy []byte
	if len(s.pcrs) > 0 {
		// Calculate policy digest for the selected PCRs
		sess, err := tpm2.StartAuthSession{
			NonceCaller: tpm2.TPM2BNonce{Buffer: make([]byte, 32)},
			SessionType: tpm2.TPMSETrial,
			AuthHash:    tpm2.TPMAlgSHA256,
		}.Execute(tpm)
		if err != nil {
			return nil, fmt.Errorf("failed to start trial session: %w", err)
		}
		defer tpm2.FlushContext{FlushHandle: sess.SessionHandle}.Execute(tpm)

		_, err = tpm2.PolicyPCR{
			PolicySession: sess.SessionHandle,
			Pcrs:          s.makePCRSelection(),
		}.Execute(tpm)
		if err != nil {
			return nil, fmt.Errorf("failed to apply PCR policy: %w", err)
		}

		pgd, err := tpm2.PolicyGetDigest{
			PolicySession: sess.SessionHandle,
		}.Execute(tpm)
		if err != nil {
			return nil, fmt.Errorf("failed to get policy digest: %w", err)
		}
		authPolicy = pgd.PolicyDigest.Buffer
	}

	// 2. Seal the data using TPM_ALG_KEYEDHASH
	inPublic := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: false,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{
				Scheme: tpm2.TPMAlgNull,
			},
		}),
	}
	if len(authPolicy) > 0 {
		inPublic.AuthPolicy = tpm2.TPM2BDigest{Buffer: authPolicy}
	}

	createResponse, err := tpm2.Create{
		ParentHandle: primary.ObjectHandle,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: data}),
			},
		},
		InPublic: tpm2.New2B(inPublic),
	}.Execute(tpm)
	if err != nil {
		return nil, err
	}

	// We return the concatenated Private and Public portions as the persistent blob
	priv := tpm2.Marshal(createResponse.OutPrivate)
	pub := tpm2.Marshal(createResponse.OutPublic)

	blob := make([]byte, 2+len(priv)+len(pub))
	blob[0] = byte(len(priv) >> 8)
	blob[1] = byte(len(priv) & 0xff)
	copy(blob[2:], priv)
	copy(blob[2+len(priv):], pub)

	return blob, nil
}

func (s *TPMKeyStore) unseal(blob []byte) ([]byte, error) {
	if len(blob) < 4 {
		return nil, fmt.Errorf("invalid tpm blob")
	}

	privLen := (int(blob[0]) << 8) | int(blob[1])
	if len(blob) < 2+privLen {
		return nil, fmt.Errorf("invalid tpm blob length")
	}

	privBytes := blob[2 : 2+privLen]
	pubBytes := blob[2+privLen:]

	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privBytes)
	if err != nil {
		return nil, err
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubBytes)
	if err != nil {
		return nil, err
	}

	tpm, err := linuxtpm.Open(s.tpmPath)
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	// 1. Re-create the Primary Key
	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext{FlushHandle: primary.ObjectHandle}.Execute(tpm)

	// 2. Load the sealed object
	load, err := tpm2.Load{
		ParentHandle: primary.ObjectHandle,
		InPrivate:    *priv,
		InPublic:     *pub,
	}.Execute(tpm)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext{FlushHandle: load.ObjectHandle}.Execute(tpm)

	// 3. Unseal
	unsealCmd := tpm2.Unseal{
		ItemHandle: load.ObjectHandle,
	}

	if len(s.pcrs) > 0 {
		// Satisfy PCR policy using a policy session
		sess, sessClose, err := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, fmt.Errorf("failed to start policy session: %w", err)
		}
		defer sessClose()

		_, err = tpm2.PolicyPCR{
			PolicySession: sess.Handle(),
			Pcrs:          s.makePCRSelection(),
		}.Execute(tpm)
		if err != nil {
			return nil, fmt.Errorf("failed to satisfy PCR policy: %w", err)
		}

		unseal, err := unsealCmd.Execute(tpm, sess)
		if err != nil {
			return nil, err
		}
		return unseal.OutData.Buffer, nil
	}

	unseal, err := unsealCmd.Execute(tpm)
	if err != nil {
		return nil, err
	}

	return unseal.OutData.Buffer, nil
}

func (s *TPMKeyStore) makePCRSelection() tpm2.TPMLPCRSelection {
	max := 0
	for _, p := range s.pcrs {
		if p > max {
			max = p
		}
	}
	mask := make([]byte, (max/8)+1)
	for _, p := range s.pcrs {
		mask[p/8] |= 1 << (uint(p) % 8)
	}
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: mask,
			},
		},
	}
}
