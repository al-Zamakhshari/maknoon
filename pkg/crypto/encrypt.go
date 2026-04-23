package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/awnumar/memguard"
)

// bufferPool reuses buffers to reduce GC pressure.
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, ChunkSize+32)
		return &b
	},
}

// EncryptStream symmetrically encrypts data from r to w using a passphrase and specified profile.
func EncryptStream(r io.Reader, w io.Writer, password []byte, flags byte, concurrency int, profileID byte) error {
	return EncryptStreamWithEvents(r, w, password, flags, concurrency, profileID, nil)
}

// EncryptStreamWithEvents is the extended version of EncryptStream that supports telemetry.
func EncryptStreamWithEvents(r io.Reader, w io.Writer, password []byte, flags byte, concurrency int, profileID byte, eventStream chan<- EngineEvent) error {
	profile := DefaultProfile()
	if profileID != 0 {
		var err error
		profile, err = GetProfile(profileID, nil)
		if err != nil {
			return err
		}
	}

	// 1. Generate random Salt for KDF
	salt := make([]byte, profile.SaltSize())
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	// 2. Derive Key
	key := profile.DeriveKey(password, salt)
	defer SafeClear(key)

	// 3. Setup AEAD & Random Base Nonce
	aead, err := profile.NewAEAD(key)
	if err != nil {
		return err
	}
	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return err
	}

	// 4. Write Header: Magic (4) | Version/ProfileID (1) | Flags (1) | Salt (N) | BaseNonce (N)
	if flags&FlagStealth == 0 {
		if _, err := w.Write([]byte(MagicHeader)); err != nil {
			return err
		}
	}
	if _, err := w.Write([]byte{profile.ID(), flags}); err != nil {
		return err
	}
	if _, err := w.Write(salt); err != nil {
		return err
	}
	if _, err := w.Write(baseNonce); err != nil {
		return err
	}

	// 5. Stream Encrypt Chunks
	return streamEncrypt(r, w, aead, baseNonce, concurrency, eventStream)
}

// EncryptStreamWithPublicKeys encrypts data from r to w for one or more recipients.
func EncryptStreamWithPublicKeys(r io.Reader, w io.Writer, pubKeys [][]byte, flags byte, concurrency int, profileID byte) error {
	return EncryptStreamWithPublicKeysAndEvents(r, w, pubKeys, nil, flags, concurrency, profileID, nil)
}

// EncryptStreamWithPublicKeysAndEvents is the extended version of EncryptStreamWithPublicKeys that supports telemetry.
func EncryptStreamWithPublicKeysAndEvents(r io.Reader, w io.Writer, pubKeys [][]byte, signingKey []byte, flags byte, concurrency int, profileID byte, eventStream chan<- EngineEvent) error {
	profile := DefaultProfile()
	if profileID != 0 {
		var err error
		profile, err = GetProfile(profileID, nil)
		if err != nil {
			return err
		}
	}

	if len(pubKeys) == 0 {
		return fmt.Errorf("at least one public key is required")
	}
	if len(pubKeys) > 255 {
		return fmt.Errorf("too many recipients (max 255)")
	}

	// Generate FEK in a secure enclave
	fekRaw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, fekRaw); err != nil {
		return err
	}
	fekEnclave := memguard.NewBufferFromBytes(fekRaw).Seal()
	SafeClear(fekRaw)
	// No defer destroy here because we pass it to workers, we should destroy after workers are done.
	// Actually, streamEncrypt accepts cipher.AEAD, we can derive it here.

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
			return fmt.Errorf("failed to encapsulate for a recipient: %w", err)
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
		return err
	}
	aead, err := profile.NewAEAD(fekBuf.Bytes())
	fekBuf.Destroy() // Wipe immediately after creating AEAD
	if err != nil {
		return err
	}

	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return err
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
			return fmt.Errorf("failed to generate integrated signature: %w", err)
		}
		signature = sig
	}

	if flags&FlagStealth == 0 {
		if _, err := w.Write([]byte(MagicHeaderAsym)); err != nil {
			return err
		}
	}
	if _, err := w.Write([]byte{profile.ID(), flags, byte(len(recs))}); err != nil {
		return err
	}

	if profile.ID() >= 128 {
		if dp, ok := profile.(*DynamicProfile); ok {
			if _, err := w.Write(dp.Pack()); err != nil {
				return err
			}
		}
	}

	for _, r := range recs {
		if _, err := w.Write(r.pubKeyHash); err != nil {
			return err
		}
		if _, err := w.Write(r.ciphertext); err != nil {
			return err
		}
	}

	if len(signature) > 0 {
		if _, err := w.Write(signature); err != nil {
			return err
		}
	}

	if _, err := w.Write(baseNonce); err != nil {
		return err
	}

	return streamEncrypt(r, w, aead, baseNonce, concurrency, eventStream)
}

// EncryptStreamWithPublicKeysAndSigner is the internal implementation supporting optional integrated signing.
func EncryptStreamWithPublicKeysAndSigner(r io.Reader, w io.Writer, pubKeys [][]byte, signingKey []byte, flags byte, concurrency int, profileID byte) error {
	return EncryptStreamWithPublicKeysAndEvents(r, w, pubKeys, signingKey, flags, concurrency, profileID, nil)
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

func streamEncrypt(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte, concurrency int, eventStream chan<- EngineEvent) error {
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}

	if concurrency == 1 {
		return streamEncryptSequential(r, w, aead, baseNonce, eventStream)
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

	return encryptionSequencer(w, results, errChan, eventStream)
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
			errChan <- err
			return
		}
	}
}

func encryptionSequencer(w io.Writer, results <-chan encryptResult, errChan <-chan error, eventStream chan<- EngineEvent) error {
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
			return err
		}
		totalProcessed += int64(len(data))
		if eventStream != nil {
			eventStream <- EventChunkProcessed{
				BytesProcessed: int64(len(data)),
				TotalProcessed: totalProcessed,
			}
		}
		return nil
	})
}

func writeChunk(w io.Writer, data []byte) error {
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	return nil
}

func streamEncryptSequential(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte, eventStream chan<- EngineEvent) error {
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufferPool.Put(bufPtr)

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
				return err
			}
			totalProcessed += int64(len(ciphertext))
			if eventStream != nil {
				eventStream <- EventChunkProcessed{
					BytesProcessed: int64(len(ciphertext)),
					TotalProcessed: totalProcessed,
				}
			}
			chunkIndex++
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}
