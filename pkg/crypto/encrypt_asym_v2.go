package crypto

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/awnumar/memguard"
)

// EncryptStreamAsymV2 encrypts r→w for one or more recipients using the V2 wire format (MAK3).
//
// V2 asymmetric improvements over V1 (MAKA):
//   - 2-byte flags field (uint16 LE) with room to grow
//   - TLV extension block for forward-compatible metadata
//   - Header MAC: HMAC-SHA256(fek, header_bytes) for key commitment — prevents
//     header-swap attacks where a ciphertext decrypts under two different keys
//   - Stream terminator: 0x00000000 after last chunk for truncation detection
//
// The THRESHOLD TLV (TLVTagThreshold) is set automatically when thresholdK >= 2.
// Set thresholdK=0 to disable threshold (standard multi-recipient mode).
func EncryptStreamAsymV2(r io.Reader, w io.Writer, pubKeys [][]byte, signingKey []byte,
	thresholdK int, flags uint16, tlvs []TLVEntry, concurrency int, profileID byte, ectx *EngineContext) error {

	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}
	if len(pubKeys) == 0 {
		return &ErrFormat{Reason: "at least one recipient public key is required"}
	}
	if len(pubKeys) > 255 {
		return &ErrFormat{Reason: "too many recipients (max 255)"}
	}

	profile := DefaultProfile()
	if profileID != 0 {
		var err error
		profile, err = GetProfile(profileID, nil)
		if err != nil {
			return &ErrFormat{Reason: fmt.Sprintf("unknown profile %d: %v", profileID, err)}
		}
	}

	// Integrate signing flag.
	if len(signingKey) > 0 {
		flags |= uint16(FlagSigned)
	}

	// 1. Generate random FEK in a memguard enclave.
	fekRaw := make([]byte, 32)
	if _, err := randFull(fekRaw); err != nil {
		return &ErrIO{Path: "stream", Reason: "failed to generate FEK"}
	}
	fekEnclave := memguard.NewBufferFromBytes(fekRaw).Seal()
	SafeClear(fekRaw)

	// 2. Wrap FEK for each recipient.
	type recipientBlock struct {
		hash    []byte
		wrapped []byte
	}
	recs := make([]recipientBlock, len(pubKeys))
	for i, pk := range pubKeys {
		wrapped, err := profile.WrapFEK(pk, byte(flags), fekEnclave)
		if err != nil {
			return &ErrCrypto{Reason: fmt.Sprintf("WrapFEK for recipient %d: %v", i+1, err)}
		}
		recs[i] = recipientBlock{
			hash:    Sha256Sum(pk)[:4],
			wrapped: wrapped,
		}
	}

	// 3. Open FEK enclave to set up AEAD.
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

	// 4. Compute integrated signature (if signing key provided).
	var signature []byte
	if len(signingKey) > 0 {
		// Commitment: MAK3 | FormatVersion | ProfileID | FEK | BaseNonce
		commitment := make([]byte, 0, 4+1+1+32+len(baseNonce))
		commitment = append(commitment, []byte(MagicHeaderV2Asym)...)
		commitment = append(commitment, FormatVersionV2Asym, profile.ID())
		commitment = append(commitment, fekBuf.Bytes()...)
		commitment = append(commitment, baseNonce...)
		sig, sigErr := profile.Sign(commitment, signingKey)
		if sigErr != nil {
			fekBuf.Destroy()
			return &ErrCrypto{Reason: fmt.Sprintf("signing failed: %v", sigErr)}
		}
		signature = sig
	}

	// 5. Inject THRESHOLD TLV when threshold mode is active.
	if thresholdK >= 2 {
		tlvs = append(tlvs, TLVEntry{
			Tag:   TLVTagThreshold,
			Value: []byte{byte(thresholdK), byte(len(pubKeys))},
		})
	}

	// 6. Build header bytes for HeaderMAC (everything before the MAC itself).
	extBytes := EncodeTLVs(tlvs)
	var hdrBuf bytes.Buffer
	hdrBuf.WriteString(MagicHeaderV2Asym)
	hdrBuf.WriteByte(FormatVersionV2Asym)
	hdrBuf.WriteByte(profile.ID())
	binary.Write(&hdrBuf, binary.LittleEndian, flags)                 //nolint:errcheck
	hdrBuf.WriteByte(byte(len(pubKeys)))                              // RecipientCount
	binary.Write(&hdrBuf, binary.LittleEndian, uint16(len(extBytes))) //nolint:errcheck
	hdrBuf.Write(extBytes)
	for _, rec := range recs {
		hdrBuf.Write(rec.hash)
		hdrBuf.Write(rec.wrapped)
	}
	if len(signature) > 0 {
		hdrBuf.Write(signature)
	}
	hdrBuf.Write(baseNonce)

	// 7. Compute HeaderMAC = HMAC-SHA256(fek, header_bytes).
	mac := ComputeHeaderMAC(fekBuf.Bytes(), hdrBuf.Bytes())
	fekBuf.Destroy()

	// 8. Write header + MAC to w.
	if _, err := w.Write(hdrBuf.Bytes()); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}
	if _, err := w.Write(mac); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}

	ectx.Emit(EventHandshakeComplete{})

	// 9. Encrypt chunks.
	// Re-open FEK enclave to build the AEAD for stream encryption.
	fekBuf2, err := fekEnclave.Open()
	if err != nil {
		return &ErrCrypto{Reason: "failed to re-open FEK enclave for stream encryption"}
	}
	aead2, err := profile.NewAEAD(fekBuf2.Bytes())
	fekBuf2.Destroy()
	if err != nil {
		return &ErrCrypto{Reason: fmt.Sprintf("NewAEAD (stream): %v", err)}
	}

	if err := streamEncrypt(r, w, aead2, baseNonce, concurrency, ectx); err != nil {
		return err
	}

	// 10. Write stream terminator.
	return writeChunkTerminator(w)
}

// DecryptStreamAsymV2 decrypts a V2 asymmetric (MAK3) file from r using the recipient's private key.
// r must point to the very beginning of the file (including the MAK3 magic).
//
// Returns profileID, flags (uint16), parsed TLV extensions, and any error.
// The HeaderMAC is verified (key commitment) before any plaintext is written to w.
func DecryptStreamAsymV2(r io.Reader, w io.Writer, privKey []byte, senderKey []byte,
	concurrency int, ectx *EngineContext) (profileID byte, flags uint16, tlvs []TLVEntry, err error) {

	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}
	if w == nil {
		w = io.Discard
	}

	// TeeReader captures header bytes for MAC verification.
	var hdrBuf bytes.Buffer
	tr := io.TeeReader(r, &hdrBuf)

	// Read magic (4 bytes).
	magicBuf := make([]byte, 4)
	if _, err = io.ReadFull(tr, magicBuf); err != nil {
		err = &ErrIO{Path: "input", Reason: "failed to read magic"}
		return
	}
	if string(magicBuf) != MagicHeaderV2Asym {
		err = &ErrFormat{Reason: fmt.Sprintf("expected MAK3 magic, got %q", string(magicBuf))}
		return
	}

	// FormatVersion (1 byte).
	versionBuf := make([]byte, 1)
	if _, err = io.ReadFull(tr, versionBuf); err != nil {
		err = &ErrIO{Path: "input", Reason: "failed to read format version"}
		return
	}
	if versionBuf[0] != FormatVersionV2Asym {
		err = &ErrFormat{Reason: fmt.Sprintf("unsupported MAK3 format version %d", versionBuf[0])}
		return
	}

	// ProfileID (1 byte).
	pidBuf := make([]byte, 1)
	if _, err = io.ReadFull(tr, pidBuf); err != nil {
		err = &ErrIO{Path: "input", Reason: "failed to read profile ID"}
		return
	}
	profileID = pidBuf[0]

	// Flags (2 bytes LE uint16).
	flagsBuf := make([]byte, 2)
	if _, err = io.ReadFull(tr, flagsBuf); err != nil {
		err = &ErrIO{Path: "input", Reason: "failed to read flags"}
		return
	}
	flags = binary.LittleEndian.Uint16(flagsBuf)

	// RecipientCount (1 byte).
	rcBuf := make([]byte, 1)
	if _, err = io.ReadFull(tr, rcBuf); err != nil {
		err = &ErrIO{Path: "input", Reason: "failed to read recipient count"}
		return
	}
	recipientCount := int(rcBuf[0])

	// ExtLen + TLV block.
	extLenBuf := make([]byte, 2)
	if _, err = io.ReadFull(tr, extLenBuf); err != nil {
		err = &ErrIO{Path: "input", Reason: "failed to read ExtLen"}
		return
	}
	extLen := binary.LittleEndian.Uint16(extLenBuf)
	var extBytes []byte
	if extLen > 0 {
		extBytes = make([]byte, extLen)
		if _, err = io.ReadFull(tr, extBytes); err != nil {
			err = &ErrIO{Path: "input", Reason: "failed to read TLV block"}
			return
		}
	}
	tlvs = DecodeTLVs(extBytes)

	// Get profile.
	profile, profileErr := GetProfile(profileID, nil)
	if profileErr != nil {
		err = &ErrFormat{Reason: fmt.Sprintf("unknown profile %d", profileID)}
		return
	}

	myHash := Sha256Sum(DerivePublicKey(privKey, profileID))[:4]
	blockSize := profile.RecipientBlockSize()

	// Read all recipient blocks, trying to unwrap our own.
	var fekEnclave *memguard.Enclave
	for i := 0; i < recipientCount; i++ {
		hashBuf := make([]byte, 4)
		if _, err = io.ReadFull(tr, hashBuf); err != nil {
			err = &ErrIO{Path: "input", Reason: "failed to read recipient hash"}
			return
		}
		material := make([]byte, blockSize)
		if _, err = io.ReadFull(tr, material); err != nil {
			err = &ErrIO{Path: "input", Reason: "failed to read recipient block"}
			return
		}

		if fekEnclave == nil && bytesEqual(hashBuf, myHash) {
			enc, unwrapErr := profile.UnwrapFEK(privKey, byte(flags), material)
			if unwrapErr == nil {
				fekEnclave = enc
			}
		}
	}
	if fekEnclave == nil {
		err = &ErrAuthentication{Reason: "no recipient block matches the provided private key"}
		return
	}

	// Skip integrated signature (if present).
	if flags&uint16(FlagSigned) != 0 {
		sigBuf := make([]byte, profile.SIGSize())
		if _, err = io.ReadFull(tr, sigBuf); err != nil {
			err = &ErrIO{Path: "input", Reason: "failed to read signature"}
			return
		}
		// TODO: verify signature against senderKey when provided
	}

	// Read BaseNonce.
	fekBuf, openErr := fekEnclave.Open()
	if openErr != nil {
		err = &ErrCrypto{Reason: "failed to open FEK enclave"}
		return
	}
	aead, aeadErr := profile.NewAEAD(fekBuf.Bytes())
	if aeadErr != nil {
		fekBuf.Destroy()
		err = &ErrCrypto{Reason: fmt.Sprintf("NewAEAD: %v", aeadErr)}
		return
	}

	baseNonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(tr, baseNonce); err != nil {
		fekBuf.Destroy()
		err = &ErrIO{Path: "input", Reason: "failed to read base nonce"}
		return
	}

	// Snapshot header bytes and compute expected MAC.
	headerBytes := hdrBuf.Bytes()
	mac := make([]byte, HeaderMACSize)
	if _, err = io.ReadFull(r, mac); err != nil {
		fekBuf.Destroy()
		err = &ErrIO{Path: "input", Reason: "failed to read header MAC"}
		return
	}

	if !VerifyHeaderMAC(fekBuf.Bytes(), headerBytes, mac) {
		fekBuf.Destroy()
		err = &ErrAuthentication{Reason: "V2 asymmetric header MAC verification failed — header may be tampered"}
		return
	}
	fekBuf.Destroy()

	// Re-open for chunk decryption.
	fekBuf2, openErr := fekEnclave.Open()
	if openErr != nil {
		err = &ErrCrypto{Reason: "failed to re-open FEK enclave for stream decryption"}
		return
	}
	aead2, aeadErr := profile.NewAEAD(fekBuf2.Bytes())
	fekBuf2.Destroy()
	if aeadErr != nil {
		err = &ErrCrypto{Reason: fmt.Sprintf("NewAEAD (stream): %v", aeadErr)}
		return
	}

	ectx.Emit(EventHandshakeComplete{})
	err = streamDecryptV2(r, w, aead2, baseNonce, ectx)
	return
}

// bytesEqual compares two byte slices in constant time.
// Used for recipient hash matching to avoid timing side-channels.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var acc byte
	for i := range a {
		acc |= a[i] ^ b[i]
	}
	return acc == 0
}
