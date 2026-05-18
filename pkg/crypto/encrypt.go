package crypto

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/awnumar/memguard"
)

// EncryptStream symmetrically encrypts data from r to w using a passphrase and specified profile.
func EncryptStream(r io.Reader, w io.Writer, password []byte, flags byte, concurrency int, profileID byte) error {
	ectx := &EngineContext{
		Context: context.Background(),
		Policy:  &HumanPolicy{},
	}
	return EncryptStreamWithEvents(r, w, password, flags, concurrency, profileID, ectx)
}

// EncryptStreamWithEvents is the extended version of EncryptStream that supports telemetry.
func EncryptStreamWithEvents(r io.Reader, w io.Writer, password []byte, flags byte, concurrency int, profileID byte, ectx *EngineContext) error {
	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}
	profile := DefaultProfile()
	if profileID != 0 {
		var err error
		profile, err = GetProfile(profileID, nil)
		if err != nil {
			return &ErrFormat{Reason: fmt.Sprintf("failed to get profile %d: %v", profileID, err)}
		}
	}

	// 1. Generate random Salt for KDF
	salt := make([]byte, profile.SaltSize())
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return &ErrIO{Path: "stream", Reason: fmt.Sprintf("failed to read random salt: %v", err)}
	}

	// 2. Derive Key
	key := profile.DeriveKey(password, salt)
	defer SafeClear(key)

	// 3. Setup AEAD & Random Base Nonce
	aead, err := profile.NewAEAD(key)
	if err != nil {
		return &ErrCrypto{Reason: fmt.Sprintf("failed to setup AEAD: %v", err)}
	}
	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return &ErrIO{Path: "stream", Reason: fmt.Sprintf("failed to read base nonce: %v", err)}
	}

	// 4. Write Header: Magic (4) | Version/ProfileID (1) | Flags (1) | Salt (N) | BaseNonce (N)
	if flags&FlagStealth == 0 {
		if _, err := w.Write([]byte(MagicHeader)); err != nil {
			return &ErrIO{Path: "output", Reason: err.Error()}
		}
	}
	if _, err := w.Write([]byte{profile.ID(), flags}); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}
	if _, err := w.Write(salt); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}
	if _, err := w.Write(baseNonce); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}

	ectx.Emit(EventHandshakeComplete{})

	// 5. Stream Encrypt Chunks
	return streamEncrypt(r, w, aead, baseNonce, concurrency, ectx)
}

// EncryptStreamNoHeader performs symmetric encryption without writing a magic header (Stealth mode core).
func EncryptStreamNoHeader(r io.Reader, w io.Writer, password []byte, flags byte, concurrency int, profileID byte, ectx *EngineContext) error {
	profile, err := GetProfile(profileID, nil)
	if err != nil {
		return &ErrFormat{Reason: fmt.Sprintf("failed to get profile %d: %v", profileID, err)}
	}

	salt := make([]byte, profile.SaltSize())
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return &ErrIO{Path: "stream", Reason: fmt.Sprintf("failed to read random salt: %v", err)}
	}

	key := profile.DeriveKey(password, salt)
	defer SafeClear(key)

	aead, err := profile.NewAEAD(key)
	if err != nil {
		return &ErrCrypto{Reason: fmt.Sprintf("failed to setup AEAD: %v", err)}
	}

	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return &ErrIO{Path: "stream", Reason: fmt.Sprintf("failed to read base nonce: %v", err)}
	}

	if _, err := w.Write([]byte{profile.ID(), flags}); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}
	if _, err := w.Write(salt); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}
	if _, err := w.Write(baseNonce); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}

	return streamEncrypt(r, w, aead, baseNonce, concurrency, ectx)
}

// EncryptStreamWithPublicKeys encrypts data from r to w for one or more recipients.
func EncryptStreamWithPublicKeys(r io.Reader, w io.Writer, pubKeys [][]byte, flags byte, concurrency int, profileID byte) error {
	ectx := &EngineContext{
		Context: context.Background(),
		Policy:  &HumanPolicy{},
	}
	return EncryptStreamWithPublicKeysAndEvents(r, w, pubKeys, nil, flags, concurrency, profileID, ectx)
}

// EncryptStreamWithPublicKeysAndEvents is the extended version of EncryptStreamWithPublicKeys that supports telemetry.
func EncryptStreamWithPublicKeysAndEvents(r io.Reader, w io.Writer, pubKeys [][]byte, signingKey []byte, flags byte, concurrency int, profileID byte, ectx *EngineContext) error {
	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}
	profile := DefaultProfile()
	if profileID != 0 {
		var err error
		profile, err = GetProfile(profileID, nil)
		if err != nil {
			return &ErrFormat{Reason: fmt.Sprintf("failed to get profile %d: %v", profileID, err)}
		}
	}

	if len(pubKeys) == 0 {
		return &ErrFormat{Reason: "at least one public key is required"}
	}
	if len(pubKeys) > 255 {
		return &ErrFormat{Reason: "too many recipients (max 255)"}
	}

	// Generate FEK in a secure enclave
	fekRaw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, fekRaw); err != nil {
		return &ErrIO{Path: "stream", Reason: "failed to generate random FEK"}
	}
	fekEnclave := memguard.NewBufferFromBytes(fekRaw).Seal()
	SafeClear(fekRaw)

	type recipientHeader struct {
		pubKeyHash []byte // 4 bytes of SHA256(pubKey)
		ciphertext []byte
	}
	var recs []recipientHeader

	if len(signingKey) > 0 {
		flags |= FlagSigned
	}

	for _, pkBytes := range pubKeys {
		wrappedMaterial, err := profile.WrapFEK(pkBytes, flags, fekEnclave)
		if err != nil {
			return &ErrCrypto{Reason: fmt.Sprintf("failed to encapsulate for a recipient: %v", err)}
		}

		h := Sha256Sum(pkBytes)[:4]
		recs = append(recs, recipientHeader{
			pubKeyHash: h,
			ciphertext: wrappedMaterial,
		})
	}

	// Instantiate AEAD from FEK
	fekBuf, err := fekEnclave.Open()
	if err != nil {
		return &ErrCrypto{Reason: "failed to open secure FEK enclave"}
	}
	aead, err := profile.NewAEAD(fekBuf.Bytes())
	fekBuf.Destroy() // Wipe immediately after creating AEAD
	if err != nil {
		return &ErrCrypto{Reason: fmt.Sprintf("failed to setup AEAD: %v", err)}
	}

	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return &ErrIO{Path: "stream", Reason: "failed to read base nonce"}
	}

	var signature []byte
	if len(signingKey) > 0 {
		commitment := make([]byte, 0, 4+1+1+32+len(baseNonce))
		commitment = append(commitment, []byte(MagicHeaderAsym)...)
		commitment = append(commitment, profile.ID(), flags)

		// Re-open fek briefly for signature commitment
		fb, _ := fekEnclave.Open()
		commitment = append(commitment, fb.Bytes()...)
		fb.Destroy()

		commitment = append(commitment, baseNonce...)

		sig, err := profile.Sign(commitment, signingKey)
		if err != nil {
			return &ErrCrypto{Reason: fmt.Sprintf("failed to generate integrated signature: %v", err)}
		}
		signature = sig
	}

	if flags&FlagStealth == 0 {
		if _, err := w.Write([]byte(MagicHeaderAsym)); err != nil {
			return &ErrIO{Path: "output", Reason: err.Error()}
		}
	}
	if _, err := w.Write([]byte{profile.ID(), flags, byte(len(recs))}); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}

	if profile.ID() >= 128 {
		if dp, ok := profile.(*DynamicProfile); ok {
			if _, err := w.Write(dp.Pack()); err != nil {
				return &ErrIO{Path: "output", Reason: err.Error()}
			}
		}
	}

	for _, r := range recs {
		if _, err := w.Write(r.pubKeyHash); err != nil {
			return &ErrIO{Path: "output", Reason: err.Error()}
		}
		if _, err := w.Write(r.ciphertext); err != nil {
			return &ErrIO{Path: "output", Reason: err.Error()}
		}
	}

	if len(signature) > 0 {
		if _, err := w.Write(signature); err != nil {
			return &ErrIO{Path: "output", Reason: err.Error()}
		}
	}

	if _, err := w.Write(baseNonce); err != nil {
		return &ErrIO{Path: "output", Reason: err.Error()}
	}

	ectx.Emit(EventHandshakeComplete{})

	return streamEncrypt(r, w, aead, baseNonce, concurrency, ectx)
}

// EncryptStreamWithPublicKeysAndSigner is the internal implementation supporting optional integrated signing.
func EncryptStreamWithPublicKeysAndSigner(r io.Reader, w io.Writer, pubKeys [][]byte, signingKey []byte, flags byte, concurrency int, profileID byte) error {
	ectx := &EngineContext{
		Context: context.Background(),
		Policy:  &HumanPolicy{},
	}
	return EncryptStreamWithPublicKeysAndEvents(r, w, pubKeys, signingKey, flags, concurrency, profileID, ectx)
}

// Deprecated: Use EncryptStreamWithPublicKeys
func EncryptStreamWithPublicKey(r io.Reader, w io.Writer, pubKeyBytes []byte, flags byte, concurrency int, profileID byte) error {
	return EncryptStreamWithPublicKeys(r, w, [][]byte{pubKeyBytes}, flags, concurrency, profileID)
}

type encryptJob struct {
	index uint64
	data  []byte
}

type encryptResult struct {
	index uint64
	data  []byte
	err   error
}

func streamEncrypt(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte, concurrency int, ectx *EngineContext) error {
	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
	}
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}

	if concurrency == 1 {
		return streamEncryptSequential(r, w, aead, baseNonce, ectx)
	}

	sem := make(chan struct{}, concurrency*4)
	jobs := make(chan encryptJob, concurrency*2)
	results := make(chan encryptResult, concurrency*2)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go encryptionWorker(&wg, jobs, results, aead, baseNonce, sem)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	errChan := make(chan error, 1)
	go encryptionReader(r, jobs, errChan, sem)

	return encryptionSequencer(w, results, errChan, ectx)
}

func encryptionWorker(wg *sync.WaitGroup, jobs <-chan encryptJob, results chan<- encryptResult, aead cipher.AEAD, baseNonce []byte, sem chan struct{}) {
	defer wg.Done()
	nonce := make([]byte, aead.NonceSize())
	nonceTail := len(nonce) - 8

	for job := range jobs {
		copy(nonce, baseNonce)
		binary.LittleEndian.PutUint64(nonce[nonceTail:], binary.LittleEndian.Uint64(baseNonce[nonceTail:])^job.index)

		ciphertext := aead.Seal(nil, nonce, job.data, nil)

		SafeClear(job.data)
		ptr := &job.data
		bufferPool.Put(ptr)
		<-sem

		results <- encryptResult{index: job.index, data: ciphertext}
	}
}

func encryptionReader(r io.Reader, jobs chan<- encryptJob, errChan chan<- error, sem chan struct{}) {
	defer close(jobs)
	chunkIndex := uint64(0)

	// Reuse readBuf within the reader.
	readBuf := make([]byte, ChunkSize)

	for {
		sem <- struct{}{}

		n, err := r.Read(readBuf)
		if n > 0 {
			workerBufPtr := bufferPool.Get().(*[]byte)
			workerBuf := *workerBufPtr
			if cap(workerBuf) < n {
				workerBuf = make([]byte, n)
			} else {
				workerBuf = workerBuf[:n]
			}
			copy(workerBuf, readBuf[:n])

			jobs <- encryptJob{index: chunkIndex, data: workerBuf}
			chunkIndex++
		} else {
			<-sem
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			errChan <- &ErrIO{Path: "input", Reason: err.Error()}
			return
		}
	}
}

func encryptionSequencer(w io.Writer, results <-chan encryptResult, errChan <-chan error, ectx *EngineContext) error {
	// Adapt the channel
	seqResults := make(chan sequencerResult)
	go func() {
		for r := range results {
			seqResults <- sequencerResult(r)
		}
		close(seqResults)
	}()

	totalProcessed := int64(0)
	return runSequencer(w, seqResults, errChan, func(w io.Writer, data []byte) error {
		if err := writeChunk(w, data); err != nil {
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

func writeChunk(w io.Writer, data []byte) error {
	var lenBuf [4]byte // stack-allocated — avoids one heap alloc per 64KB chunk
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	return nil
}

func streamEncryptSequential(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte, ectx *EngineContext) error {
	if ectx == nil {
		ectx = &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}
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
		n, err := r.Read(buf)
		if n > 0 {
			copy(nonce, baseNonce)
			counterBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(counterBytes, chunkIndex)

			offset := len(nonce) - 8
			for i := 0; i < 8; i++ {
				nonce[offset+i] ^= counterBytes[i]
			}

			ciphertext := aead.Seal(nil, nonce, buf[:n], nil)

			if err := writeChunk(w, ciphertext); err != nil {
				return &ErrIO{Path: "output", Reason: err.Error()}
			}
			totalProcessed += int64(len(ciphertext))
			ectx.Emit(EventChunkProcessed{
				BytesProcessed: int64(len(ciphertext)),
				TotalProcessed: totalProcessed,
			})
			chunkIndex++
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return &ErrIO{Path: "input", Reason: err.Error()}
		}
	}
	return nil
}
