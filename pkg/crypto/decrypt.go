package crypto
import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
)


// DecryptStream decrypts data from r to w using a passphrase.
func DecryptStream(r io.Reader, w io.Writer, password []byte, concurrency int) (byte, error) {
	// 1. Read Fixed Header (Magic, Version, Flags)
	fixedHeader := make([]byte, 6)
	if _, err := io.ReadFull(r, fixedHeader); err != nil {
		return 0, err
	}

	if string(fixedHeader[:4]) != MagicHeader {
		return 0, errors.New("invalid file format: missing MAKN magic header")
	}

	profile, err := GetProfile(fixedHeader[4], r)
	if err != nil {
		return 0, err
	}
	flags := fixedHeader[5]

	// 2. Read Salt & Base Nonce
	salt := make([]byte, profile.SaltSize())
	if _, err := io.ReadFull(r, salt); err != nil {
		return 0, err
	}
	baseNonce := make([]byte, profile.NonceSize())
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return 0, err
	}

	// 3. Derive Key
	key := profile.DeriveKey(password, salt)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// 4. Setup AEAD
	aead, err := profile.NewAEAD(key)
	if err != nil {
		return 0, err
	}

	// 5. Stream Decrypt Chunks
	return flags, streamDecrypt(r, w, aead, baseNonce, concurrency)
}

// DecryptStreamWithPrivateKey decrypts data from r to w using a Post-Quantum Private Key.
func DecryptStreamWithPrivateKey(r io.Reader, w io.Writer, privKeyBytes []byte, concurrency int) (byte, error) {
	// 1. Read Fixed Header (Magic, Version, Flags)
	fixedHeader := make([]byte, 6)
	if _, err := io.ReadFull(r, fixedHeader); err != nil {
		return 0, err
	}

	if string(fixedHeader[:4]) != MagicHeaderAsym {
		return 0, errors.New("invalid file format: missing MAKA magic header")
	}

	profile, err := GetProfile(fixedHeader[4], r)
	if err != nil {
		return 0, err
	}
	flags := fixedHeader[5]

	// 2. Read KEM Ciphertext
	ct := make([]byte, profile.KEMCiphertextSize())
	if _, err := io.ReadFull(r, ct); err != nil {
		return 0, err
	}

	// 3. Read Base Nonce
	baseNonce := make([]byte, profile.NonceSize())
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return 0, err
	}

	// 4. Decapsulate Shared Secret
	ss, err := profile.KEMDecapsulate(privKeyBytes, ct)
	if err != nil {
		return 0, fmt.Errorf("decapsulation failed: %w", err)
	}
	defer func() {
		for i := range ss {
			ss[i] = 0
		}
	}()

	// 5. Setup AEAD
	aead, err := profile.NewAEAD(ss)
	if err != nil {
		return 0, err
	}

	// 6. Stream Decrypt Chunks
	return flags, streamDecrypt(r, w, aead, baseNonce, concurrency)
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

func streamDecrypt(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte, concurrency int) error {
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}

	if concurrency == 1 {
		return streamDecryptSequential(r, w, aead, baseNonce)
	}

	jobs := make(chan decryptJob, concurrency*2)
	results := make(chan decryptResult, concurrency*2)
	var wg sync.WaitGroup

	// Workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go decryptionWorker(&wg, jobs, results, aead, baseNonce)
	}

	// Closer
	go func() {
		wg.Wait()
		close(results)
	}()

	// Reader
	errChan := make(chan error, 1)
	go decryptionReader(r, jobs, errChan)

	// Writer (Sequencer)
	return decryptionSequencer(w, results, errChan)
}

func decryptionWorker(wg *sync.WaitGroup, jobs <-chan decryptJob, results chan<- decryptResult, aead cipher.AEAD, baseNonce []byte) {
	defer wg.Done()
	for job := range jobs {
		nonce := make([]byte, aead.NonceSize())
		copy(nonce, baseNonce)
		counterBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(counterBytes, job.index)
		
		// XOR counter into the last 8 bytes of the nonce
		offset := len(nonce) - 8
		for i := 0; i < 8; i++ {
			nonce[offset+i] ^= counterBytes[i]
		}

		plaintext, err := aead.Open(nil, nonce, job.data, nil)
		if err != nil {
			results <- decryptResult{err: errors.New("authentication failed: incorrect key or corrupted data")}
			return
		}
		results <- decryptResult{index: job.index, data: plaintext}
	}
}

func decryptionReader(r io.Reader, jobs chan<- decryptJob, errChan chan<- error) {
	defer close(jobs)
	chunkIndex := uint64(0)
	lenBuf := make([]byte, 4)
	for {
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			if err == io.EOF {
				break
			}
			errChan <- err
			return
		}

		chunkLen := binary.LittleEndian.Uint32(lenBuf)
		if chunkLen > uint32(ChunkSize+16) {
			errChan <- errors.New("corrupted payload: chunk size exceeds maximum")
			return
		}

		ciphertext := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, ciphertext); err != nil {
			errChan <- err
			return
		}

		jobs <- decryptJob{index: chunkIndex, data: ciphertext}
		chunkIndex++
	}
}

func decryptionSequencer(w io.Writer, results <-chan decryptResult, errChan <-chan error) error {
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
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		chunkLen := binary.LittleEndian.Uint32(lenBuf)
		if chunkLen > uint32(ChunkSize+16) {
			return errors.New("corrupted payload: chunk size exceeds maximum")
		}

		ciphertext := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, ciphertext); err != nil {
			return err
		}

		copy(nonce, baseNonce)
		counterBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(counterBytes, chunkIndex)
		// XOR counter into the last 8 bytes of the nonce
		offset := len(nonce) - 8
		for i := 0; i < 8; i++ {
			nonce[offset+i] ^= counterBytes[i]
		}

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return errors.New("authentication failed: incorrect key or corrupted data")
		}

		if _, err := w.Write(plaintext); err != nil {
			return err
		}
		chunkIndex++
	}
	return nil
}
