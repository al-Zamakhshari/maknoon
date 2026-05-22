package crypto

// Threshold Decryption — K-of-N
//
// Encrypt a file to N recipient public keys, requiring any K to cooperate to
// decrypt. The FEK is split into N shares with Shamir SSS; each share is
// wrapped (HPKE-encrypted) to the corresponding recipient's public key.
//
// Wire format (extends MagicHeaderAsym):
//   MAKA | profileID | flags|FlagThreshold | recipientCount(N) | threshold(K)
//   | [pubKeyHash(4) + wrappedShare] * N | baseNonce | ciphertext
//
// Decrypt flow:
//   1. Each recipient runs DecryptThresholdCollectShare → saves their share to a file.
//   2. Once K share files are available, DecryptThresholdCombine loads them,
//      recombines the FEK with Shamir, and decrypts the ciphertext.
//
// Reuses: SplitSecret / CombineShares (shares.go), WrapFEK / UnwrapFEK
// (profile_v1.go), streamDecrypt (decrypt.go), Sha256Sum (pipeline.go).

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/awnumar/memguard"
)

// recomputeShareChecksum attaches the HMAC-SHA256 checksum to a Share whose
// Data was stored externally (e.g., wrapped via HPKE) without the checksum.
// This is needed when reassembling threshold shares before CombineShares.
func recomputeShareChecksum(s *Share) {
	h := hmac.New(sha256.New, shardChecksumKey)
	h.Write([]byte{s.Version, s.Threshold, s.Index})
	h.Write(s.Data)
	sum := h.Sum(nil)
	s.Checksum = sum[:ChecksumSize]
}

// ThresholdShare is the on-disk representation of one recipient's Shamir share.
// It is serialised to JSON and stored alongside the encrypted file until
// K parties have contributed their share and decryption can proceed.
type ThresholdShare struct {
	Version   int    `json:"version"`
	Threshold int    `json:"threshold"` // K
	Total     int    `json:"total"`     // N
	Index     int    `json:"index"`     // 1-based share index
	ShareData []byte `json:"share_data"`
}

// EncryptStreamThreshold encrypts r → w to N recipient public keys with
// a K-of-N threshold: any K keyholders must cooperate to decrypt.
// K must satisfy 2 ≤ K ≤ N ≤ 255.
func EncryptStreamThreshold(r io.Reader, w io.Writer, pubKeys [][]byte, threshold int,
	flags byte, concurrency int, profileID byte, ectx *EngineContext) error {

	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}

	n := len(pubKeys)
	if n == 0 || n > 255 {
		return &ErrFormat{Reason: "threshold encrypt: recipient count must be 1–255"}
	}
	if threshold < 2 || threshold > n {
		return &ErrFormat{Reason: fmt.Sprintf("threshold encrypt: K=%d must satisfy 2 ≤ K ≤ N=%d", threshold, n)}
	}

	profile := DefaultProfile()
	if profileID != 0 {
		var err error
		profile, err = GetProfile(profileID, nil)
		if err != nil {
			return &ErrFormat{Reason: fmt.Sprintf("unknown profile %d: %v", profileID, err)}
		}
	}

	flags |= FlagThreshold

	// 1. Generate FEK and split into N shares.
	fekRaw := make([]byte, 32)
	if _, err := randFull(fekRaw); err != nil {
		return &ErrIO{Path: "stream", Reason: "failed to generate FEK"}
	}
	defer SafeClear(fekRaw)

	shares, err := SplitSecret(fekRaw, threshold, n)
	if err != nil {
		return &ErrCrypto{Reason: fmt.Sprintf("Shamir split failed: %v", err)}
	}

	// 2. Wrap each share to the corresponding recipient.
	type recipientBlock struct {
		hash    []byte
		wrapped []byte
	}
	blocks := make([]recipientBlock, n)
	for i, pk := range pubKeys {
		shareEnclave := memguard.NewBufferFromBytes(shares[i].Data).Seal()
		wrapped, err := profile.WrapFEK(pk, flags, shareEnclave)
		if err != nil {
			return &ErrCrypto{Reason: fmt.Sprintf("WrapFEK for recipient %d: %v", i+1, err)}
		}
		blocks[i] = recipientBlock{
			hash:    Sha256Sum(pk)[:4],
			wrapped: wrapped,
		}
	}

	// 3. Build AEAD from FEK.
	fekEnclave := memguard.NewBufferFromBytes(fekRaw).Seal()
	fekBuf, err := fekEnclave.Open()
	if err != nil {
		return &ErrCrypto{Reason: "failed to open FEK enclave"}
	}
	aead, err := profile.NewAEAD(fekBuf.Bytes())
	fekBuf.Destroy()
	if err != nil {
		return &ErrCrypto{Reason: fmt.Sprintf("NewAEAD: %v", err)}
	}

	baseNonce := make([]byte, aead.NonceSize())
	if _, err := randFull(baseNonce); err != nil {
		return &ErrIO{Path: "stream", Reason: "failed to generate nonce"}
	}

	// 4. Write header.
	if _, err := w.Write([]byte(MagicHeaderAsym)); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}
	if _, err := w.Write([]byte{profile.ID(), flags, byte(n), byte(threshold)}); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}
	for _, b := range blocks {
		if _, err := w.Write(b.hash); err != nil {
			return &ErrIO{Path: "output", Reason: err.Error()}
		}
		if _, err := w.Write(b.wrapped); err != nil {
			return &ErrIO{Path: "output", Reason: err.Error()}
		}
	}
	if _, err := w.Write(baseNonce); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}

	ectx.Emit(EventHandshakeComplete{})
	return streamEncrypt(r, w, aead, baseNonce, concurrency, ectx)
}

// DecryptThresholdCollectShare reads the threshold-encrypted file and extracts
// this recipient's Shamir share using their private key. The returned
// ThresholdShare should be serialised and stored until K shares are available.
func DecryptThresholdCollectShare(r io.Reader, privKey []byte, profileID byte) (*ThresholdShare, error) {
	// Read and validate header.
	magic, pid, flags, recipientCount, err := ReadHeader(r, false)
	if err != nil {
		return nil, err
	}
	if magic != MagicHeaderAsym {
		return nil, &ErrFormat{Reason: "not a threshold-encrypted file (wrong magic)"}
	}
	if flags&FlagThreshold == 0 {
		return nil, &ErrFormat{Reason: "file was not encrypted with --threshold; use regular decrypt"}
	}

	// Read threshold byte (written after recipientCount in the header).
	threshByte := make([]byte, 1)
	if _, err := io.ReadFull(r, threshByte); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read threshold byte"}
	}
	threshold := int(threshByte[0])
	total := int(recipientCount)

	if profileID == 0 {
		profileID = pid
	}
	profile, err := GetProfile(profileID, nil)
	if err != nil {
		return nil, &ErrFormat{Reason: fmt.Sprintf("unknown profile %d", pid)}
	}

	myHash := Sha256Sum(DerivePublicKey(privKey, pid))[:4]
	blockSize := profile.RecipientBlockSize()

	var myShare *ThresholdShare
	for i := 0; i < total; i++ {
		h := make([]byte, 4)
		if _, err := io.ReadFull(r, h); err != nil {
			return nil, &ErrIO{Path: "input", Reason: "failed to read recipient hash"}
		}
		material := make([]byte, blockSize)
		if _, err := io.ReadFull(r, material); err != nil {
			return nil, &ErrIO{Path: "input", Reason: "failed to read recipient material"}
		}

		if bytes.Equal(h, myHash) && myShare == nil {
			// Unwrap this share.
			shareEnclave, err := profile.UnwrapFEK(privKey, flags, material)
			if err != nil {
				return nil, &ErrAuthentication{Reason: fmt.Sprintf("failed to unwrap share: %v", err)}
			}
			shareBuf, err := shareEnclave.Open()
			if err != nil {
				return nil, &ErrCrypto{Reason: "failed to open share enclave"}
			}
			shareData := make([]byte, shareBuf.Size())
			copy(shareData, shareBuf.Bytes())
			shareBuf.Destroy()

			myShare = &ThresholdShare{
				Version:   1,
				Threshold: threshold,
				Total:     total,
				Index:     i + 1, // 1-based
				ShareData: shareData,
			}
		}
	}

	if myShare == nil {
		return nil, &ErrAuthentication{Reason: "no recipient entry matches your private key"}
	}
	return myShare, nil
}

// DecryptThresholdCombine recovers the FEK by combining K ThresholdShares and
// decrypts the ciphertext from src (re-opened for reading from the start),
// writing plaintext to w or outPath. At least threshold shares must be provided.
func DecryptThresholdCombine(src io.Reader, w io.Writer, outPath string, shares []*ThresholdShare, ectx *EngineContext) error {
	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}
	if len(shares) == 0 {
		return &ErrFormat{Reason: "no shares provided"}
	}
	threshold := shares[0].Threshold
	if len(shares) < threshold {
		return &ErrAuthentication{Reason: fmt.Sprintf("insufficient shares: have %d, need %d", len(shares), threshold)}
	}

	// Convert ThresholdShare → Share for CombineShares.
	// The HMAC checksum must be recomputed: we wrapped only the raw share Data
	// (not the checksum) during encryption, so it wasn't preserved in the share file.
	sssShares := make([]Share, len(shares))
	for i, ts := range shares {
		s := Share{
			Version:   ShareVersion,
			Threshold: byte(ts.Threshold),
			Index:     byte(ts.Index),
			Data:      ts.ShareData,
		}
		recomputeShareChecksum(&s)
		sssShares[i] = s
	}
	fek, err := CombineShares(sssShares)
	if err != nil {
		return &ErrCrypto{Reason: fmt.Sprintf("Shamir combine failed: %v", err)}
	}
	defer SafeClear(fek)

	// Parse header from src to reach the baseNonce.
	_, pid, flags, recipientCount, err := ReadHeader(src, false)
	if err != nil {
		return err
	}

	profile, err := GetProfile(pid, nil)
	if err != nil {
		return &ErrFormat{Reason: fmt.Sprintf("unknown profile %d", pid)}
	}

	// Skip threshold byte + all recipient blocks.
	threshBuf := make([]byte, 1)
	if _, err := io.ReadFull(src, threshBuf); err != nil {
		return &ErrIO{Path: "input", Reason: "failed to read threshold byte"}
	}
	blockSize := profile.RecipientBlockSize()
	skipBuf := make([]byte, 4+blockSize)
	for i := 0; i < int(recipientCount); i++ {
		if _, err := io.ReadFull(src, skipBuf); err != nil {
			return &ErrIO{Path: "input", Reason: "failed to skip recipient block"}
		}
	}

	// Skip signature if present.
	if flags&FlagSigned != 0 {
		sigBuf := make([]byte, profile.SIGSize())
		if _, err := io.ReadFull(src, sigBuf); err != nil {
			return &ErrIO{Path: "input", Reason: "failed to skip signature"}
		}
	}

	// Read baseNonce.
	aead, err := profile.NewAEAD(fek)
	if err != nil {
		return &ErrCrypto{Reason: fmt.Sprintf("NewAEAD: %v", err)}
	}
	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(src, baseNonce); err != nil {
		return &ErrIO{Path: "input", Reason: "failed to read baseNonce"}
	}

	// Decrypt in a goroutine and pipe through FinalizeRestoration so
	// decompression and archive extraction work transparently.
	pr, pw := io.Pipe()
	go func() {
		err := streamDecrypt(src, pw, aead, baseNonce, 0, ectx)
		pw.CloseWithError(err)
	}()
	e := NewStreamEngine(nil)
	return e.FinalizeRestoration(ectx, pr, w, flags, outPath, slog.Default())
}

// ThresholdShareToJSON serialises a ThresholdShare to JSON bytes.
func ThresholdShareToJSON(s *ThresholdShare) ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// ThresholdShareFromJSON deserialises a ThresholdShare from JSON bytes.
func ThresholdShareFromJSON(data []byte) (*ThresholdShare, error) {
	var s ThresholdShare
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, &ErrFormat{Reason: fmt.Sprintf("invalid threshold share file: %v", err)}
	}
	return &s, nil
}

// randFull fills b with cryptographic random bytes.
func randFull(b []byte) (int, error) {
	return io.ReadFull(rand.Reader, b)
}
