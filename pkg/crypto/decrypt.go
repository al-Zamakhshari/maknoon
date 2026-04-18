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
func DecryptStream(r io.Reader, w io.Writer, password []byte, concurrency int) (byte, error) {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil {
		return 0, err
	}
	if string(magic) != MagicHeader {
		return 0, errors.New("not a valid Maknoon file (symmetric)")
	}

	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, err
	}
	profileID := header[0]
	flags := header[1]

	profile, err := GetProfile(profileID, r)
	if err != nil {
		return 0, err
	}

	salt := make([]byte, profile.SaltSize())
	if _, err := io.ReadFull(r, salt); err != nil {
		return 0, err
	}

	key := profile.DeriveKey(password, salt)
	defer SafeClear(key)

	aead, err := profile.NewAEAD(key)
	if err != nil {
		return 0, err
	}

	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return 0, err
	}

	return flags, streamDecrypt(r, w, aead, baseNonce, concurrency)
}

// DecryptStreamWithPrivateKey decrypts data from r to w using a private key.
func DecryptStreamWithPrivateKey(r io.Reader, w io.Writer, privKeyBytes []byte, concurrency int) (byte, error) {
	return DecryptStreamWithPrivateKeyAndVerifier(r, w, privKeyBytes, nil, concurrency)
}

// DecryptStreamWithPrivateKeyAndVerifier is the internal implementation supporting optional signature verification.
func DecryptStreamWithPrivateKeyAndVerifier(r io.Reader, w io.Writer, privKeyBytes []byte, senderPubKey []byte, concurrency int) (byte, error) {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil {
		return 0, err
	}
	if string(magic) != MagicHeaderAsym {
		return 0, errors.New("not a valid Maknoon file (asymmetric)")
	}

	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, err
	}
	profileID := header[0]
	flags := header[1]
	recipientCount := int(header[2])

	profile, err := GetProfile(profileID, r)
	if err != nil {
		return 0, err
	}

	kem := hpke.MLKEM768X25519()
	// Hybrid enc size: 1120. Wrapped FEK: 32. Total recipient block payload: 1152.
	const encSize = 1120
	const recipientPayloadSize = encSize + 32

	privKey, err := kem.NewPrivateKey(privKeyBytes)
	if err != nil {
		return 0, fmt.Errorf("invalid private key: %w", err)
	}

	var fekEnclave *memguard.Enclave 

	// Search for our recipient block
	found := false
	pubKeyBytes := privKey.PublicKey().Bytes()
	myHash := sha256Sum(pubKeyBytes)[:4]

	for i := 0; i < recipientCount; i++ {
		h := make([]byte, 4)
		if _, err := io.ReadFull(r, h); err != nil {
			return 0, err
		}

		payload := make([]byte, recipientPayloadSize)
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, err
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
		return 0, errors.New("no matching recipient block found or decryption failed")
	}

	// Signature verification
	var signature []byte
	if flags&FlagSigned != 0 {
		sig := make([]byte, profile.SIGSize())
		if _, err := io.ReadFull(r, sig); err != nil {
			return 0, err
		}
		signature = sig
	}

	baseNonce := make([]byte, profile.NonceSize())
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return 0, err
	}

	// Open enclave to get AEAD
	fekBuf, err := fekEnclave.Open()
	if err != nil {
		return 0, err
	}
	aead, err := profile.NewAEAD(fekBuf.Bytes())
	
	if flags&FlagSigned != 0 {
		if senderPubKey == nil {
			fekBuf.Destroy()
			return 0, errors.New("sender public key not provided for signed file")
		}
		commitment := make([]byte, 0, 4+1+1+32+len(baseNonce))
		commitment = append(commitment, []byte(MagicHeaderAsym)...)
		commitment = append(commitment, profileID, flags)
		commitment = append(commitment, fekBuf.Bytes()...)
		commitment = append(commitment, baseNonce...)

		if !profile.Verify(commitment, signature, senderPubKey) {
			fekBuf.Destroy()
			return 0, errors.New("integrated signature verification failed")
		}
	}
	fekBuf.Destroy()

	return flags, streamDecrypt(r, w, aead, baseNonce, concurrency)
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
			for job := range jobs {
				nonce := make([]byte, aead.NonceSize())
				copy(nonce, baseNonce)
				counterBytes := make([]byte, 8)
				binary.LittleEndian.PutUint64(counterBytes, job.index)
				offset := len(nonce) - 8
				for i := 0; i < 8; i++ {
					nonce[offset+i] ^= counterBytes[i]
				}

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

	nextIndex := uint64(0)
	pending := make(map[uint64][]byte)
	for {
		select {
		case err := <-errChan:
			return err
		case res, ok := <-results:
			if !ok {
				if len(pending) > 0 {
					return fmt.Errorf("decryption pipeline failed: missing chunks")
				}
				return nil
			}
			if res.err != nil {
				return res.err
			}

			pending[res.index] = res.data

			for {
				data, exists := pending[nextIndex]
				if !exists {
					break
				}
				if _, err := w.Write(data); err != nil {
					return err
				}
				SafeClear(data)
				delete(pending, nextIndex)
				nextIndex++
			}
		}
	}
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
