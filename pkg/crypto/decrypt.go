package crypto

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"
)

// V2ParsedHeader holds the decoded state of a V2 header and the AEAD/nonce
// needed to continue streaming decryption. After parsing, r is positioned
// immediately after the HeaderMAC field (ready for chunk reads).
type V2ParsedHeader struct {
	ProfileID byte
	Flags     uint16
	TLVs      []TLVEntry
	AEAD      cipher.AEAD
	BaseNonce []byte
}

// ParseV2SymHeader reads and validates a V2 symmetric (MAK2) header from r,
// returning a V2ParsedHeader and leaving r positioned at the first chunk.
// This is the parse-only path used by unprotectInternal to obtain the real
// flags before FinalizeRestoration begins (decompression depends on flags).
func ParseV2SymHeader(r io.Reader, password []byte) (*V2ParsedHeader, error) {
	var hdrBuf bytes.Buffer
	tr := io.TeeReader(r, &hdrBuf)

	magicBuf := make([]byte, 4)
	if _, err := io.ReadFull(tr, magicBuf); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read magic"}
	}
	if string(magicBuf) != MagicHeaderV2Sym {
		return nil, &ErrFormat{Reason: fmt.Sprintf("expected MAK2 magic, got %q", string(magicBuf))}
	}
	versionBuf := make([]byte, 1)
	if _, err := io.ReadFull(tr, versionBuf); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read format version"}
	}
	if versionBuf[0] != FormatVersionV2Sym {
		return nil, &ErrFormat{Reason: fmt.Sprintf("unsupported MAK2 format version %d", versionBuf[0])}
	}
	pidBuf := make([]byte, 1)
	if _, err := io.ReadFull(tr, pidBuf); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read profile ID"}
	}
	profileID := pidBuf[0]
	flagsBuf := make([]byte, 2)
	if _, err := io.ReadFull(tr, flagsBuf); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read flags"}
	}
	flags := binary.LittleEndian.Uint16(flagsBuf)
	extLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(tr, extLenBuf); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read ExtLen"}
	}
	extLen := binary.LittleEndian.Uint16(extLenBuf)
	var extBytes []byte
	if extLen > 0 {
		extBytes = make([]byte, extLen)
		if _, err := io.ReadFull(tr, extBytes); err != nil {
			return nil, &ErrIO{Path: "input", Reason: "failed to read TLV block"}
		}
	}
	tlvs := DecodeTLVs(extBytes)
	saltLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(tr, saltLenBuf); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read SaltLen"}
	}
	salt := make([]byte, saltLenBuf[0])
	if _, err := io.ReadFull(tr, salt); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read salt"}
	}
	profile, profileErr := GetProfile(profileID, nil)
	if profileErr != nil {
		return nil, &ErrFormat{Reason: fmt.Sprintf("unknown profile %d", profileID)}
	}
	fek := profile.DeriveKey(password, salt)
	defer SafeClear(fek)
	aead, aeadErr := profile.NewAEAD(fek)
	if aeadErr != nil {
		return nil, &ErrCrypto{Reason: fmt.Sprintf("NewAEAD: %v", aeadErr)}
	}
	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(tr, baseNonce); err != nil {
		return nil, &ErrIO{Path: "input", Reason: "failed to read base nonce"}
	}
	headerBytes := hdrBuf.Bytes()
	mac := make([]byte, HeaderMACSize)
	if _, err := io.ReadFull(r, mac); err != nil { // read from r, not tr
		return nil, &ErrIO{Path: "input", Reason: "failed to read header MAC"}
	}
	if !VerifyHeaderMAC(fek, headerBytes, mac) {
		return nil, &ErrAuthentication{Reason: "header MAC verification failed: wrong passphrase or tampered header"}
	}
	return &V2ParsedHeader{
		ProfileID: profileID,
		Flags:     flags,
		TLVs:      tlvs,
		AEAD:      aead,
		BaseNonce: baseNonce,
	}, nil
}

// DecryptStreamV2 symmetrically decrypts a V2-format (.makn MAK2) file from r.
// r must point to the very beginning of the file (including the MAK2 magic bytes).
//
// Returns the profileID, flags (uint16), parsed TLV extensions, and any error.
// Authentication of both the header (via HeaderMAC) and each chunk (AES-GCM)
// is performed before any plaintext is written to w.
func DecryptStreamV2(r io.Reader, w io.Writer, password []byte, concurrency int, ectx *EngineContext) (profileID byte, flags uint16, tlvs []TLVEntry, err error) {
	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}
	if w == nil {
		w = io.Discard
	}

	// Use a TeeReader so every byte read from r is also captured in hdrBuf.
	// This lets us compute the HeaderMAC over exactly the bytes we consumed.
	var hdrBuf bytes.Buffer
	tr := io.TeeReader(r, &hdrBuf)

	// Read magic (4 bytes).
	magicBuf := make([]byte, 4)
	if _, err = io.ReadFull(tr, magicBuf); err != nil {
		err = &ErrIO{Path: "input", Reason: "failed to read magic"}
		return
	}
	if string(magicBuf) != MagicHeaderV2Sym {
		err = &ErrFormat{Reason: fmt.Sprintf("expected MAK2 magic, got %q", string(magicBuf))}
		return
	}

	// FormatVersion (1 byte).
	versionBuf := make([]byte, 1)
	if _, err = io.ReadFull(tr, versionBuf); err != nil {
		err = &ErrIO{Path: "input", Reason: "failed to read format version"}
		return
	}
	if versionBuf[0] != FormatVersionV2Sym {
		err = &ErrFormat{Reason: fmt.Sprintf("unsupported MAK2 format version %d (expected %d)", versionBuf[0], FormatVersionV2Sym)}
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

	// SaltLen + Salt.
	saltLenBuf := make([]byte, 1)
	if _, err = io.ReadFull(tr, saltLenBuf); err != nil {
		err = &ErrIO{Path: "input", Reason: "failed to read SaltLen"}
		return
	}
	salt := make([]byte, saltLenBuf[0])
	if _, err = io.ReadFull(tr, salt); err != nil {
		err = &ErrIO{Path: "input", Reason: "failed to read salt"}
		return
	}

	// Get profile and derive FEK.
	profile, profileErr := GetProfile(profileID, nil)
	if profileErr != nil {
		err = &ErrFormat{Reason: fmt.Sprintf("unknown profile %d", profileID)}
		return
	}
	fek := profile.DeriveKey(password, salt)
	defer SafeClear(fek)

	aead, aeadErr := profile.NewAEAD(fek)
	if aeadErr != nil {
		err = &ErrCrypto{Reason: fmt.Sprintf("NewAEAD: %v", aeadErr)}
		return
	}

	// BaseNonce.
	baseNonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(tr, baseNonce); err != nil {
		err = &ErrIO{Path: "input", Reason: "failed to read base nonce"}
		return
	}

	// At this point hdrBuf holds all bytes consumed via tr (magic through nonce).
	headerBytes := hdrBuf.Bytes()

	// HeaderMAC (32 bytes) — read from r directly (not via tr, so it's not in hdrBuf).
	mac := make([]byte, HeaderMACSize)
	if _, err = io.ReadFull(r, mac); err != nil {
		err = &ErrIO{Path: "input", Reason: "failed to read header MAC"}
		return
	}

	// Verify header MAC — key commitment check.
	if !VerifyHeaderMAC(fek, headerBytes, mac) {
		err = &ErrAuthentication{Reason: "header MAC verification failed: wrong passphrase or tampered header"}
		return
	}

	ectx.Emit(EventHandshakeComplete{})

	// Decrypt chunks using the V2 terminator-aware loop.
	err = streamDecryptV2(r, w, aead, baseNonce, ectx)
	return
}

// streamDecryptV2 decrypts V2-format chunks from r to w.
// Unlike V1, V2 uses a 4-byte 0x00000000 terminator to signal clean end-of-stream,
// enabling detection of truncation attacks.
func streamDecryptV2(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte, ectx *EngineContext) error {
	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}
	nonce := make([]byte, aead.NonceSize())
	nonceTail := len(nonce) - 8
	chunkIndex := uint64(0)
	totalProcessed := int64(0)

	for {
		// Read 4-byte chunk length.
		var chunkLen uint32
		if err := binary.Read(r, binary.LittleEndian, &chunkLen); err != nil {
			if err == io.EOF {
				return &ErrIO{Path: "input", Reason: "unexpected EOF: missing V2 stream terminator (file may be truncated)"}
			}
			return &ErrIO{Path: "input", Reason: fmt.Sprintf("reading chunk length: %v", err)}
		}

		// 0x00000000 = clean end-of-stream.
		if chunkLen == 0 {
			return nil
		}

		// Guard against unreasonably large chunks (max 1 MB ciphertext = 64 KB + overhead).
		const maxChunkCipher = (4 * 1024 * 1024) + 64
		if chunkLen > maxChunkCipher {
			return &ErrFormat{Reason: fmt.Sprintf("chunk %d: length %d exceeds maximum — file may be corrupt", chunkIndex, chunkLen)}
		}

		ciphertext := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, ciphertext); err != nil {
			return &ErrIO{Path: "input", Reason: fmt.Sprintf("reading chunk %d: %v", chunkIndex, err)}
		}

		// Derive per-chunk nonce by XOR-ing baseNonce tail with chunk index.
		copy(nonce, baseNonce)
		binary.LittleEndian.PutUint64(nonce[nonceTail:], binary.LittleEndian.Uint64(baseNonce[nonceTail:])^chunkIndex)

		plaintext, err := aead.Open(ciphertext[:0], nonce, ciphertext, nil)
		if err != nil {
			return &ErrAuthentication{
				Reason: fmt.Sprintf("chunk %d authentication failed — file is corrupt or truncated", chunkIndex),
			}
		}

		if _, err := w.Write(plaintext); err != nil {
			return &ErrIO{Path: "output", Reason: err.Error()}
		}
		totalProcessed += int64(len(plaintext))
		ectx.Emit(EventChunkProcessed{
			BytesProcessed: int64(len(plaintext)),
			TotalProcessed: totalProcessed,
		})
		chunkIndex++
	}
}

// DecryptStream symmetrically decrypts data from r to w using a passphrase.
func DecryptStream(r io.Reader, w io.Writer, password []byte, concurrency int, stealth bool) (byte, byte, error) {
	ectx := &EngineContext{
		Context: context.Background(),
		Policy:  &HumanPolicy{},
	}
	return DecryptStreamWithEvents(r, w, password, concurrency, stealth, ectx)
}

// DecryptStreamWithEvents is the extended version of DecryptStream that supports telemetry.
// It automatically detects V1 (MAKN) and V2 (MAK2) symmetric formats.
func DecryptStreamWithEvents(r io.Reader, w io.Writer, password []byte, concurrency int, stealth bool, ectx *EngineContext) (byte, byte, error) {
	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}
	if w == nil {
		w = io.Discard
	}
	// 1. Read Header (detects V1 MAKN or V2 MAK2 magic)
	magic, profileID, flags, _, err := ReadHeader(r, stealth)
	if err != nil {
		return 0, 0, err
	}

	// V2 symmetric dispatch: ReadHeader consumed the 4-byte MAK2 magic.
	// Prepend it back so DecryptStreamV2 can read a complete file.
	if magic == MagicHeaderV2Sym {
		fullReader := io.MultiReader(bytes.NewReader([]byte(magic)), r)
		pid, v2flags, _, v2err := DecryptStreamV2(fullReader, w, password, concurrency, ectx)
		return pid, byte(v2flags), v2err
	}

	// In stealth mode, we expect caller to know it's symmetric
	if !stealth && magic != MagicHeaderSym {
		return 0, 0, &ErrFormat{Reason: "expected symmetric magic header"}
	}

	profile, err := GetProfile(profileID, nil)
	if err != nil {
		return 0, 0, &ErrFormat{Reason: fmt.Sprintf("failed to get profile %d: %v", profileID, err)}
	}

	// 2. Read Salt and Base Nonce
	salt := make([]byte, profile.SaltSize())
	if _, err := io.ReadFull(r, salt); err != nil {
		return 0, 0, &ErrIO{Path: "input", Reason: "failed to read salt"}
	}

	key := profile.DeriveKey(password, salt)
	defer SafeClear(key)

	aead, err := profile.NewAEAD(key)
	if err != nil {
		return 0, 0, &ErrCrypto{Reason: fmt.Sprintf("failed to setup AEAD: %v", err)}
	}

	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return 0, 0, &ErrIO{Path: "input", Reason: "failed to read base nonce"}
	}

	ectx.Emit(EventHandshakeComplete{})

	// 3. Stream Decrypt Chunks
	err = streamDecrypt(r, w, aead, baseNonce, concurrency, ectx)
	return profileID, flags, err
}

// DecryptStreamWithPrivateKey decrypts data from r to w using a private key.
func DecryptStreamWithPrivateKey(r io.Reader, w io.Writer, privKey []byte, senderKey []byte, concurrency int, stealth bool) (byte, byte, error) {
	ectx := &EngineContext{
		Context: context.Background(),
		Policy:  &HumanPolicy{},
	}
	return DecryptStreamWithPrivateKeyAndEvents(r, w, privKey, senderKey, concurrency, stealth, ectx)
}

// DecryptStreamWithPrivateKeyAndVerifier is a legacy shim for integrated signing.
func DecryptStreamWithPrivateKeyAndVerifier(r io.Reader, w io.Writer, privKey []byte, senderKey []byte, concurrency int, stealth bool) (byte, byte, error) {
	return DecryptStreamWithPrivateKey(r, w, privKey, senderKey, concurrency, stealth)
}

// DecryptStreamWithPrivateKeyAndEvents is the extended version of DecryptStreamWithPrivateKey that supports telemetry.
// It automatically detects V1 (MAKA) and V2 (MAK3) asymmetric formats.
func DecryptStreamWithPrivateKeyAndEvents(r io.Reader, w io.Writer, privKey []byte, senderKey []byte, concurrency int, stealth bool, ectx *EngineContext) (byte, byte, error) {
	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}
	if w == nil {
		w = io.Discard
	}
	// 1. Read Header (detects V1 MAKA or V2 MAK3 magic)
	magic, profileID, flags, recipientCount, err := ReadHeader(r, stealth)
	if err != nil {
		return 0, 0, err
	}

	// V2 asymmetric dispatch: ReadHeader consumed the 4-byte MAK3 magic.
	// Prepend it back so DecryptStreamAsymV2 can read a complete file.
	if magic == MagicHeaderV2Asym {
		fullReader := io.MultiReader(bytes.NewReader([]byte(magic)), r)
		pid, v2flags, _, v2err := DecryptStreamAsymV2(fullReader, w, privKey, senderKey, concurrency, ectx)
		return pid, byte(v2flags), v2err
	}

	if stealth {
		magic = MagicHeaderAsym
		count := make([]byte, 1)
		if _, err := io.ReadFull(r, count); err != nil {
			return 0, 0, &ErrIO{Path: "input", Reason: "failed to read recipient count in stealth mode"}
		}
		recipientCount = count[0]
	}

	// In stealth mode, we expect caller to know it's asymmetric
	if !stealth && magic != MagicHeaderAsym {
		return 0, 0, &ErrFormat{Reason: "expected asymmetric magic header"}
	}

	profile, err := GetProfile(profileID, nil)
	if err != nil {
		return 0, 0, &ErrFormat{Reason: fmt.Sprintf("failed to get profile %d: %v", profileID, err)}
	}

	if profileID >= 128 {
		if _, ok := profile.(*DynamicProfile); ok {
			packed := make([]byte, 7)
			if _, err := io.ReadFull(r, packed); err != nil {
				return 0, 0, &ErrIO{Path: "input", Reason: "failed to read dynamic profile data"}
			}
			newDP, _ := UnpackDynamicProfile(profileID, packed)
			profile = newDP
		}
	}

	// 2. Find and Unseal FEK
	myH := Sha256Sum(DerivePublicKey(privKey, profileID))[:4]
	var wrappedMaterial []byte
	found := false

	// Recipient list
	for i := 0; i < int(recipientCount); i++ {
		h := make([]byte, 4)
		if _, err := io.ReadFull(r, h); err != nil {
			return 0, 0, &ErrIO{Path: "input", Reason: "failed to read recipient hash"}
		}

		materialLen := profile.RecipientBlockSize()
		material := make([]byte, materialLen)
		if _, err := io.ReadFull(r, material); err != nil {
			return 0, 0, &ErrIO{Path: "input", Reason: "failed to read recipient material"}
		}

		if bytes.Equal(h, myH) {
			wrappedMaterial = material
			found = true
		}
	}

	if !found {
		return 0, 0, &ErrAuthentication{Reason: "no recipient matches your private key"}
	}

	// Read Signature if present
	var signature []byte
	if flags&FlagSigned != 0 {
		sigSize := profile.SIGSize()
		signature = make([]byte, sigSize)
		if _, err := io.ReadFull(r, signature); err != nil {
			return 0, 0, &ErrIO{Path: "input", Reason: "failed to read integrated signature"}
		}
	}

	baseNonce := make([]byte, profile.NonceSize())
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return 0, 0, &ErrIO{Path: "input", Reason: "failed to read base nonce"}
	}

	fekEnclave, err := profile.UnwrapFEK(privKey, flags, wrappedMaterial)
	if err != nil {
		return 0, 0, &ErrCrypto{Reason: fmt.Sprintf("failed to recover FEK: %v", err)}
	}

	// Verify Signature if present
	if flags&FlagSigned != 0 {
		if len(senderKey) == 0 {
			return 0, 0, &ErrAuthentication{Reason: "sender's public key is required for signed files"}
		}

		commitment := make([]byte, 0, 4+1+1+32+len(baseNonce))
		commitment = append(commitment, []byte(MagicHeaderAsym)...)
		commitment = append(commitment, profileID, flags)

		fb, _ := fekEnclave.Open()
		commitment = append(commitment, fb.Bytes()...)
		fb.Destroy()

		commitment = append(commitment, baseNonce...)

		if !profile.Verify(commitment, signature, senderKey) {
			return 0, 0, &ErrAuthentication{Reason: "❌ Signature Verification FAILED! The data might be corrupted or from an untrusted source"}
		}
	}

	fekBuf, err := fekEnclave.Open()
	if err != nil {
		return 0, 0, &ErrCrypto{Reason: "failed to open secure FEK enclave"}
	}
	aead, err := profile.NewAEAD(fekBuf.Bytes())
	fekBuf.Destroy()
	if err != nil {
		return 0, 0, &ErrCrypto{Reason: fmt.Sprintf("failed to setup AEAD: %v", err)}
	}

	ectx.Emit(EventHandshakeComplete{})

	// 3. Stream Decrypt Chunks
	err = streamDecrypt(r, w, aead, baseNonce, concurrency, ectx)
	return profileID, flags, err
}

type decryptJob struct {
	index uint64
	data  []byte
}

type decryptResult struct {
	index uint64
	data  []byte
	err   error
}

func streamDecrypt(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte, concurrency int, ectx *EngineContext) error {
	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}
	if w == nil {
		w = io.Discard
	}
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}

	if concurrency == 1 {
		return streamDecryptSequential(r, w, aead, baseNonce, ectx)
	}

	sem := make(chan struct{}, concurrency*4)
	jobs := make(chan decryptJob, concurrency*2)
	results := make(chan decryptResult, concurrency*2)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go decryptionWorker(&wg, jobs, results, aead, baseNonce, sem)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	errChan := make(chan error, 1)
	go decryptionReader(r, jobs, errChan, sem)

	return decryptionSequencer(w, results, errChan, ectx)
}

func decryptionWorker(wg *sync.WaitGroup, jobs <-chan decryptJob, results chan<- decryptResult, aead cipher.AEAD, baseNonce []byte, sem chan struct{}) {
	defer wg.Done()
	nonce := make([]byte, aead.NonceSize())
	nonceTail := len(nonce) - 8

	for job := range jobs {
		copy(nonce, baseNonce)
		binary.LittleEndian.PutUint64(nonce[nonceTail:], binary.LittleEndian.Uint64(baseNonce[nonceTail:])^job.index)

		plaintext, err := aead.Open(nil, nonce, job.data, nil)
		SafeClear(job.data)
		ptr := &job.data
		bufferPool.Put(ptr)
		<-sem

		results <- decryptResult{index: job.index, data: plaintext, err: err}
	}
}

func decryptionReader(r io.Reader, jobs chan<- decryptJob, errChan chan<- error, sem chan struct{}) {
	defer close(jobs)
	chunkIndex := uint64(0)

	for {
		sem <- struct{}{}
		lenBuf := make([]byte, 4)
		_, err := io.ReadFull(r, lenBuf)
		if err == io.EOF {
			<-sem
			break
		}
		if err != nil {
			<-sem
			errChan <- &ErrIO{Path: "input", Reason: err.Error()}
			return
		}

		chunkLen := binary.LittleEndian.Uint32(lenBuf)
		if chunkLen > ChunkSize+uint32(128) {
			<-sem
			errChan <- &ErrFormat{Reason: fmt.Sprintf("malformed stream: chunk too large (%d)", chunkLen)}
			return
		}

		workerBufPtr := bufferPool.Get().(*[]byte)
		workerBuf := *workerBufPtr
		workerBuf = workerBuf[:chunkLen]
		if _, err := io.ReadFull(r, workerBuf); err != nil {
			<-sem
			errChan <- &ErrIO{Path: "input", Reason: err.Error()}
			return
		}

		jobs <- decryptJob{index: chunkIndex, data: workerBuf}
		chunkIndex++
	}
}

func decryptionSequencer(w io.Writer, results <-chan decryptResult, errChan <-chan error, ectx *EngineContext) error {
	seqResults := make(chan sequencerResult)
	go func() {
		for r := range results {
			seqResults <- sequencerResult(r)
		}
		close(seqResults)
	}()

	totalProcessed := int64(0)
	return runSequencer(w, seqResults, errChan, func(w io.Writer, data []byte) error {
		if _, err := w.Write(data); err != nil {
			return &ErrIO{Path: "output", Reason: err.Error()}
		}
		totalProcessed += int64(len(data))
		ectx.Emit(EventChunkProcessed{
			BytesProcessed: int64(len(data)),
			TotalProcessed: totalProcessed,
		})
		return nil
	})
}

func streamDecryptSequential(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte, ectx *EngineContext) error {
	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}
	if w == nil {
		w = io.Discard
	}
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer func() {
		SafeClear(*bufPtr)
		bufferPool.Put(bufPtr)
	}()

	chunkIndex := uint64(0)
	totalProcessed := int64(0)
	nonce := make([]byte, aead.NonceSize())

	for {
		lenBuf := make([]byte, 4)
		_, err := io.ReadFull(r, lenBuf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return &ErrIO{Path: "input", Reason: err.Error()}
		}

		chunkLen := binary.LittleEndian.Uint32(lenBuf)
		if chunkLen > uint32(cap(buf)) {
			return &ErrFormat{Reason: "chunk too large"}
		}

		payload := buf[:chunkLen]
		if _, err := io.ReadFull(r, payload); err != nil {
			return &ErrIO{Path: "input", Reason: err.Error()}
		}

		copy(nonce, baseNonce)
		counterBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(counterBytes, chunkIndex)
		offset := len(nonce) - 8
		for i := 0; i < 8; i++ {
			nonce[offset+i] ^= counterBytes[i]
		}

		plaintext, err := aead.Open(nil, nonce, payload, nil)
		if err != nil {
			return &ErrCrypto{Reason: fmt.Sprintf("decryption failed at chunk %d: %v", chunkIndex, err)}
		}

		if _, err := w.Write(plaintext); err != nil {
			return &ErrIO{Path: "output", Reason: err.Error()}
		}
		totalProcessed += int64(len(plaintext))
		ectx.Emit(EventChunkProcessed{
			BytesProcessed: int64(len(plaintext)),
			TotalProcessed: totalProcessed,
		})
		chunkIndex++
	}
	return nil
}
