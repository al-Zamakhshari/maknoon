package crypto

import (
	"crypto/cipher"
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/awnumar/memguard"
)

// DecryptStream decrypts data from r to w using a passphrase.
func DecryptStream(r io.Reader, w io.Writer, password []byte, concurrency int, isStealth bool) (byte, []byte, error) {
	magic, profileID, flags, err := ReadHeader(r, isStealth)
	if err != nil {
		return 0, nil, err
	}

	if !isStealth && magic != MagicHeader {
		return 0, nil, errors.New("not a valid Maknoon file (symmetric)")
	}

	profile, err := GetProfile(profileID, r)
	if err != nil {
		return 0, nil, err
	}

	salt := make([]byte, profile.SaltSize())
	if _, err := io.ReadFull(r, salt); err != nil {
		return 0, nil, err
	}

	key := profile.DeriveKey(password, salt)
	defer SafeClear(key)

	aead, err := profile.NewAEAD(key)
	if err != nil {
		return 0, nil, err
	}

	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return 0, nil, err
	}

	return flags, nil, streamDecrypt(r, w, aead, baseNonce, concurrency)
}

// ReadHeader reads the magic bytes (if not stealth) and the profile/flags header.
func ReadHeader(r io.Reader, isStealth bool) (magic string, profileID byte, flags byte, err error) {
	if !isStealth {
		m := make([]byte, 4)
		if _, err := io.ReadFull(r, m); err != nil {
			return "", 0, 0, err
		}
		magic = string(m)
	}

	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return magic, 0, 0, err
	}
	profileID = header[0]
	flags = header[1]
	return magic, profileID, flags, nil
}

// DecryptStreamWithPrivateKey decrypts data from r to w using a private key.
func DecryptStreamWithPrivateKey(r io.Reader, w io.Writer, privKeyBytes []byte, concurrency int, isStealth bool) (byte, []byte, error) {
	return DecryptStreamWithPrivateKeyAndVerifier(r, w, privKeyBytes, nil, concurrency, isStealth)
}

// DecryptStreamWithPrivateKeyAndVerifier is the internal implementation supporting optional signature verification.
func DecryptStreamWithPrivateKeyAndVerifier(r io.Reader, w io.Writer, privKeyBytes []byte, senderPubKey []byte, concurrency int, isStealth bool) (byte, []byte, error) {
	if !isStealth {
		magic := make([]byte, 4)
		if _, err := io.ReadFull(r, magic); err != nil {
			return 0, nil, err
		}
		if string(magic) != MagicHeaderAsym {
			return 0, nil, errors.New("not a valid Maknoon file (asymmetric)")
		}
	}

	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	profileID := header[0]
	flags := header[1]
	recipientCount := int(header[2])

	profile, err := GetProfile(profileID, r)
	if err != nil {
		return 0, nil, err
	}

	kem := hpke.MLKEM768X25519()
	// Hybrid enc size: 1120. Wrapped FEK: 32. Total recipient block payload: 1152.
	const encSize = 1120
	const recipientPayloadSize = encSize + 32

	privKey, err := kem.NewPrivateKey(privKeyBytes)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid private key: %w", err)
	}

	var fekEnclave *memguard.Enclave

	// Search for our recipient block
	found := false
	pubKeyBytes := privKey.PublicKey().Bytes()
	myHash := Sha256Sum(pubKeyBytes)[:4]

	for i := 0; i < recipientCount; i++ {
		h := make([]byte, 4)
		if _, err := io.ReadFull(r, h); err != nil {
			return 0, nil, err
		}

		payload := make([]byte, recipientPayloadSize)
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}

		if !found && string(h) == string(myHash) {
			enclave, err := profile.UnwrapFEK(privKey, flags, payload)
			if err == nil {
				fekEnclave = enclave
				found = true
			}
		}
	}

	if !found {
		return 0, nil, errors.New("no matching recipient block found or decryption failed")
	}

	// Signature verification
	var signature []byte
	if flags&FlagSigned != 0 {
		sig := make([]byte, profile.SIGSize())
		if _, err := io.ReadFull(r, sig); err != nil {
			return 0, nil, err
		}
		signature = sig
	}

	baseNonce := make([]byte, profile.NonceSize())
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return 0, nil, err
	}

	// Open enclave to get AEAD
	fekBuf, err := fekEnclave.Open()
	if err != nil {
		return 0, nil, err
	}
	aead, err := profile.NewAEAD(fekBuf.Bytes())
	if err != nil {
		fekBuf.Destroy()
		return 0, nil, err
	}

	if flags&FlagSigned != 0 {
		if senderPubKey == nil {
			fekBuf.Destroy()
			return 0, nil, errors.New("sender public key not provided for signed file")
		}
		commitment := make([]byte, 0, 4+1+1+32+len(baseNonce))
		commitment = append(commitment, []byte(MagicHeaderAsym)...)
		commitment = append(commitment, profileID, flags)
		commitment = append(commitment, fekBuf.Bytes()...)
		commitment = append(commitment, baseNonce...)

		if !profile.Verify(commitment, signature, senderPubKey) {
			fekBuf.Destroy()
			return 0, nil, errors.New("integrated signature verification failed")
		}
	}
	fekBuf.Destroy()

	return flags, senderPubKey, streamDecrypt(r, w, aead, baseNonce, concurrency)
}

func streamDecrypt(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte, concurrency int) error {
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}

	if concurrency == 1 {
		return streamDecryptSequential(r, w, aead, baseNonce)
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

	sem := make(chan struct{}, concurrency*4)
	jobs := make(chan decryptJob, concurrency*2)
	results := make(chan decryptResult, concurrency*2)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nonce := make([]byte, aead.NonceSize())
			nonceTail := len(nonce) - 8
			for job := range jobs {
				copy(nonce, baseNonce)
				binary.LittleEndian.PutUint64(nonce[nonceTail:], binary.LittleEndian.Uint64(baseNonce[nonceTail:])^job.index)

				plaintext, err := aead.Open(nil, nonce, job.data, nil)
				// Reclaim worker buffer (ciphertext)
				SafeClear(job.data)
				ptr := &job.data
				bufferPool.Put(ptr)
				<-sem

				results <- decryptResult{index: job.index, data: plaintext, err: err}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	errChan := make(chan error, 1)
	go func() {
		defer close(jobs)
		chunkIndex := uint64(0)
		for {
			sem <- struct{}{}
			lenBuf := make([]byte, 4)
			_, err := io.ReadFull(r, lenBuf)
			if err != nil {
				<-sem
				if err == io.EOF {
					break
				}
				errChan <- err
				return
			}

			chunkLen := binary.LittleEndian.Uint32(lenBuf)
			workerBufPtr := bufferPool.Get().(*[]byte)
			workerBuf := *workerBufPtr
			if uint32(cap(workerBuf)) < chunkLen {
				workerBuf = make([]byte, chunkLen)
			} else {
				workerBuf = workerBuf[:chunkLen]
			}

			if _, err := io.ReadFull(r, workerBuf); err != nil {
				<-sem
				errChan <- err
				return
			}

			jobs <- decryptJob{index: chunkIndex, data: workerBuf}
			chunkIndex++
		}
	}()

	seqResults := make(chan sequencerResult)
	go func() {
		for r := range results {
			seqResults <- sequencerResult(r)
		}
		close(seqResults)
	}()

	return runSequencer(w, seqResults, errChan, func(w io.Writer, b []byte) error {
		if _, err := w.Write(b); err != nil {
			return err
		}
		SafeClear(b)
		return nil
	})
}

func streamDecryptSequential(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte) error {
	chunkIndex := uint64(0)
	nonce := make([]byte, aead.NonceSize())
	lenBuf := make([]byte, 4)

	for {
		_, err := io.ReadFull(r, lenBuf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		chunkLen := binary.LittleEndian.Uint32(lenBuf)
		ciphertext := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, ciphertext); err != nil {
			return err
		}

		copy(nonce, baseNonce)
		counterBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(counterBytes, chunkIndex)
		offset := len(nonce) - 8
		for i := 0; i < 8; i++ {
			nonce[offset+i] ^= counterBytes[i]
		}

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return errors.New("authentication failed: incorrect key or corrupted data")
		}

		if _, err := w.Write(plaintext); err != nil {
			SafeClear(plaintext)
			return err
		}
		SafeClear(plaintext)
		chunkIndex++
	}
	return nil
}
