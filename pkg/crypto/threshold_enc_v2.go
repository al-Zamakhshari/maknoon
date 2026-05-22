package crypto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/awnumar/memguard"
)

// EncryptStreamThresholdV2 encrypts r→w to N recipients with a K-of-N Shamir
// threshold using the V2 MAK3 wire format.
//
// Unlike EncryptStreamAsymV2 (which wraps the full FEK for each recipient),
// this function:
//  1. Generates a random FEK.
//  2. Splits the FEK into N Shamir shares (K needed to reconstruct).
//  3. Wraps each recipient's share — not the FEK — via HPKE.
//  4. Writes a MAK3 header with a THRESHOLD TLV [K, N].
//
// To decrypt, each recipient runs DecryptThresholdCollectShareV2 with their
// private key to obtain a ThresholdShare. Once K shares are collected, pass
// them to DecryptThresholdCombineV2 to reconstruct the FEK and decrypt.
//
// Constraints: 2 ≤ K ≤ N ≤ 255.
func EncryptStreamThresholdV2(r io.Reader, w io.Writer, pubKeys [][]byte,
	threshold int, flags uint16, concurrency int, profileID byte, ectx *EngineContext) error {

	n := len(pubKeys)
	if n == 0 || n > 255 {
		return &ErrFormat{Reason: "threshold encrypt V2: recipient count must be 1–255"}
	}
	if threshold < 2 || threshold > n {
		return &ErrFormat{Reason: fmt.Sprintf("threshold encrypt V2: K=%d must satisfy 2 ≤ K ≤ N=%d", threshold, n)}
	}

	profile := DefaultProfile()
	if profileID != 0 {
		var err error
		profile, err = GetProfile(profileID, nil)
		if err != nil {
			return &ErrFormat{Reason: fmt.Sprintf("unknown profile %d: %v", profileID, err)}
		}
	}

	// 1. Generate random FEK.
	fekRaw := make([]byte, 32)
	if _, err := randFull(fekRaw); err != nil {
		return &ErrIO{Path: "stream", Reason: "failed to generate FEK"}
	}
	defer SafeClear(fekRaw)

	// 2. Split FEK into N Shamir shares with threshold K.
	shares, err := SplitSecret(fekRaw, threshold, n)
	if err != nil {
		return &ErrCrypto{Reason: fmt.Sprintf("Shamir split failed: %v", err)}
	}

	// 3. Wrap each share with the corresponding recipient's public key.
	type recipientBlock struct {
		hash    []byte
		wrapped []byte
	}
	recs := make([]recipientBlock, n)
	for i, pk := range pubKeys {
		shareEnclave := memguard.NewBufferFromBytes(shares[i].Data).Seal()
		wrapped, wrapErr := profile.WrapFEK(pk, byte(flags), shareEnclave)
		if wrapErr != nil {
			return &ErrCrypto{Reason: fmt.Sprintf("WrapFEK for recipient %d: %v", i+1, wrapErr)}
		}
		recs[i] = recipientBlock{
			hash:    Sha256Sum(pk)[:4],
			wrapped: wrapped,
		}
	}

	// 4. Set up AEAD with the full FEK (not shares).
	fekEnclave := memguard.NewBufferFromBytes(fekRaw).Seal()
	fekBuf, err := fekEnclave.Open()
	if err != nil {
		return &ErrCrypto{Reason: "failed to open FEK enclave"}
	}
	aead, err := profile.NewAEAD(fekBuf.Bytes())
	if err != nil {
		fekBuf.Destroy()
		return &ErrCrypto{Reason: fmt.Sprintf("NewAEAD: %v", err)}
	}
	baseNonce := make([]byte, aead.NonceSize())
	if _, err := randFull(baseNonce); err != nil {
		fekBuf.Destroy()
		return &ErrIO{Path: "stream", Reason: "failed to generate base nonce"}
	}

	// 5. Build THRESHOLD TLV + header bytes for MAC.
	tlvs := []TLVEntry{{
		Tag:   TLVTagThreshold,
		Value: []byte{byte(threshold), byte(n)},
	}}
	extBytes := EncodeTLVs(tlvs)
	var hdrBuf bytes.Buffer
	hdrBuf.WriteString(MagicHeaderV2Asym)
	hdrBuf.WriteByte(FormatVersionV2Asym)
	hdrBuf.WriteByte(profile.ID())
	binary.Write(&hdrBuf, binary.LittleEndian, flags)                 //nolint:errcheck
	hdrBuf.WriteByte(byte(n))                                         // RecipientCount
	binary.Write(&hdrBuf, binary.LittleEndian, uint16(len(extBytes))) //nolint:errcheck
	hdrBuf.Write(extBytes)
	for _, rec := range recs {
		hdrBuf.Write(rec.hash)
		hdrBuf.Write(rec.wrapped)
	}
	hdrBuf.Write(baseNonce)

	// 6. Compute HeaderMAC keyed by the full FEK.
	mac := ComputeHeaderMAC(fekBuf.Bytes(), hdrBuf.Bytes())
	fekBuf.Destroy()

	// 7. Write header + MAC.
	if _, err := w.Write(hdrBuf.Bytes()); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}
	if _, err := w.Write(mac); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}

	// 8. Encrypt stream with FEK + write terminator.
	fekBuf2, err := fekEnclave.Open()
	if err != nil {
		return &ErrCrypto{Reason: "failed to re-open FEK enclave for stream encryption"}
	}
	aead2, err := profile.NewAEAD(fekBuf2.Bytes())
	fekBuf2.Destroy()
	if err != nil {
		return &ErrCrypto{Reason: fmt.Sprintf("NewAEAD (stream): %v", err)}
	}
	if err := streamEncrypt(r, w, aead2, baseNonce, concurrency, nil); err != nil {
		return err
	}
	return writeChunkTerminator(w)
}

// DecryptThresholdCollectShareV2 reads a V2 MAK3 threshold file and extracts
// this recipient's Shamir share using their private key.
//
// The returned ThresholdShare should be serialised with ThresholdShareToJSON
// and stored until K shares are available for DecryptThresholdCombineV2.
func DecryptThresholdCollectShareV2(r io.Reader, privKey []byte, profileID byte) (*ThresholdShare, error) {
	// TeeReader captures header bytes (used later to verify MAC once FEK is known).
	var hdrBuf bytes.Buffer
	tr := io.TeeReader(r, &hdrBuf)

	// Read MAK3 magic.
	magic := make([]byte, 4)
	if _, err := io.ReadFull(tr, magic); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read magic"}
	}
	if string(magic) != MagicHeaderV2Asym {
		return nil, &ErrFormat{Reason: fmt.Sprintf("expected MAK3 magic for threshold file, got %q", string(magic))}
	}

	// FormatVersion.
	ver := make([]byte, 1)
	if _, err := io.ReadFull(tr, ver); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read format version"}
	}
	if ver[0] != FormatVersionV2Asym {
		return nil, &ErrFormat{Reason: fmt.Sprintf("unsupported format version %d", ver[0])}
	}

	// ProfileID.
	pidBuf := make([]byte, 1)
	if _, err := io.ReadFull(tr, pidBuf); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read profile ID"}
	}
	if profileID == 0 {
		profileID = pidBuf[0]
	}

	// Flags (2 bytes LE).
	flagsBuf := make([]byte, 2)
	if _, err := io.ReadFull(tr, flagsBuf); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read flags"}
	}
	flags := binary.LittleEndian.Uint16(flagsBuf)

	// RecipientCount.
	rcBuf := make([]byte, 1)
	if _, err := io.ReadFull(tr, rcBuf); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read recipient count"}
	}
	total := int(rcBuf[0])

	// ExtLen + TLVs.
	extLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(tr, extLenBuf); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read ExtLen"}
	}
	extLen := binary.LittleEndian.Uint16(extLenBuf)
	extBytes := make([]byte, extLen)
	if extLen > 0 {
		if _, err := io.ReadFull(tr, extBytes); err != nil {
			return nil, &ErrIO{Path: "input", Reason: "failed to read TLV block"}
		}
	}
	tlvs := DecodeTLVs(extBytes)

	// Read THRESHOLD TLV.
	threshVal := FindTLV(tlvs, TLVTagThreshold)
	if len(threshVal) < 2 {
		return nil, &ErrFormat{Reason: "not a V2 threshold file: THRESHOLD TLV missing or malformed"}
	}
	threshold := int(threshVal[0])
	if total != int(threshVal[1]) {
		return nil, &ErrFormat{Reason: "THRESHOLD TLV total mismatch with RecipientCount"}
	}

	profile, err := GetProfile(profileID, nil)
	if err != nil {
		return nil, &ErrFormat{Reason: fmt.Sprintf("unknown profile %d", profileID)}
	}

	myHash := Sha256Sum(DerivePublicKey(privKey, profileID))[:4]
	blockSize := profile.RecipientBlockSize()

	// Read all recipient blocks; unwrap this recipient's share.
	var myShare *ThresholdShare
	for i := 0; i < total; i++ {
		hashBuf := make([]byte, 4)
		if _, err := io.ReadFull(tr, hashBuf); err != nil {
			return nil, &ErrIO{Path: "input", Reason: "failed to read recipient hash"}
		}
		material := make([]byte, blockSize)
		if _, err := io.ReadFull(tr, material); err != nil {
			return nil, &ErrIO{Path: "input", Reason: "failed to read recipient block"}
		}
		if myShare == nil && bytesEqual(hashBuf, myHash) {
			shareEnclave, unwrapErr := profile.UnwrapFEK(privKey, byte(flags), material)
			if unwrapErr != nil {
				return nil, &ErrAuthentication{Reason: fmt.Sprintf("failed to unwrap share: %v", unwrapErr)}
			}
			shareBuf, openErr := shareEnclave.Open()
			if openErr != nil {
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
		return nil, &ErrAuthentication{Reason: "no recipient block matches the provided private key"}
	}
	return myShare, nil
}

// DecryptThresholdCombineV2 reconstructs the FEK from K ThresholdShares and
// decrypts the V2 MAK3 threshold file from src (re-opened from the start),
// writing plaintext to w or outPath.
//
// At least threshold shares must be provided. The header MAC is verified using
// the reconstructed FEK before any plaintext is written.
func DecryptThresholdCombineV2(src io.Reader, w io.Writer, outPath string, shares []*ThresholdShare, ectx *EngineContext) error {
	if len(shares) == 0 {
		return &ErrFormat{Reason: "no shares provided"}
	}
	threshold := shares[0].Threshold
	if len(shares) < threshold {
		return &ErrAuthentication{
			Reason: fmt.Sprintf("insufficient shares: have %d, need %d", len(shares), threshold),
		}
	}

	// Reconstruct FEK from Shamir shares.
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

	// Decrypt using the V2 asymmetric path with the reconstructed FEK.
	// We parse the header manually so we can verify the HeaderMAC.
	var hdrBuf bytes.Buffer
	tr := io.TeeReader(src, &hdrBuf)

	// Read MAK3 magic.
	magicBytes := make([]byte, 4)
	if _, err := io.ReadFull(tr, magicBytes); err != nil {
		return &ErrIO{Path: "input", Reason: "failed to read magic"}
	}
	if string(magicBytes) != MagicHeaderV2Asym {
		return &ErrFormat{Reason: fmt.Sprintf("expected MAK3 magic, got %q", string(magicBytes))}
	}

	// FormatVersion + ProfileID + Flags + RecipientCount + ExtLen + TLVs.
	verPidFlagsBuf := make([]byte, 1+1+2+1+2)
	if _, err := io.ReadFull(tr, verPidFlagsBuf); err != nil {
		return &ErrIO{Path: "input", Reason: "failed to read header meta"}
	}
	extLen := binary.LittleEndian.Uint16(verPidFlagsBuf[5:7])
	pidByte := verPidFlagsBuf[1]
	recipientCount := int(verPidFlagsBuf[4])

	extBytes := make([]byte, extLen)
	if extLen > 0 {
		if _, err := io.ReadFull(tr, extBytes); err != nil {
			return &ErrIO{Path: "input", Reason: "failed to read TLV block"}
		}
	}

	// Skip all recipient blocks.
	profile, profileErr := GetProfile(pidByte, nil)
	if profileErr != nil {
		return &ErrFormat{Reason: fmt.Sprintf("unknown profile %d", pidByte)}
	}
	blockSize := profile.RecipientBlockSize()
	skipBuf := make([]byte, 4+blockSize)
	for i := 0; i < recipientCount; i++ {
		if _, err := io.ReadFull(tr, skipBuf); err != nil {
			return &ErrIO{Path: "input", Reason: "failed to skip recipient block"}
		}
	}

	// Read BaseNonce.
	aead, err := profile.NewAEAD(fek)
	if err != nil {
		return &ErrCrypto{Reason: fmt.Sprintf("NewAEAD: %v", err)}
	}
	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(tr, baseNonce); err != nil {
		return &ErrIO{Path: "input", Reason: "failed to read base nonce"}
	}

	// Verify HeaderMAC.
	headerBytes := hdrBuf.Bytes()
	mac := make([]byte, HeaderMACSize)
	if _, err := io.ReadFull(src, mac); err != nil { // read from src, not tr
		return &ErrIO{Path: "input", Reason: "failed to read header MAC"}
	}
	if !VerifyHeaderMAC(fek, headerBytes, mac) {
		return &ErrAuthentication{Reason: "V2 threshold header MAC verification failed — wrong shares or tampered file"}
	}

	// Decrypt chunks using V2 terminator-aware loop.
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(streamDecryptV2(src, pw, aead, baseNonce, nil))
	}()
	e := NewStreamEngine(nil)
	return e.FinalizeRestoration(ectx, pr, w, 0, outPath, nil)
}
