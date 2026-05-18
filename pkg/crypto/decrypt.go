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

// DecryptStream symmetrically decrypts data from r to w using a passphrase.
func DecryptStream(r io.Reader, w io.Writer, password []byte, concurrency int, stealth bool) (byte, byte, error) {
	ectx := &EngineContext{
		Context: context.Background(),
		Policy:  &HumanPolicy{},
	}
	return DecryptStreamWithEvents(r, w, password, concurrency, stealth, ectx)
}

// DecryptStreamWithEvents is the extended version of DecryptStream that supports telemetry.
func DecryptStreamWithEvents(r io.Reader, w io.Writer, password []byte, concurrency int, stealth bool, ectx *EngineContext) (byte, byte, error) {
	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}
	if w == nil {
		w = io.Discard
	}
	// 1. Read Header
	magic, profileID, flags, _, err := ReadHeader(r, stealth)
	if err != nil {
		return 0, 0, err
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
func DecryptStreamWithPrivateKeyAndEvents(r io.Reader, w io.Writer, privKey []byte, senderKey []byte, concurrency int, stealth bool, ectx *EngineContext) (byte, byte, error) {
	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}
	if w == nil {
		w = io.Discard
	}
	// 1. Read Header
	magic, profileID, flags, recipientCount, err := ReadHeader(r, stealth)
	if err != nil {
		return 0, 0, err
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
