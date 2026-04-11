package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// DecryptStream decrypts data from r to w using a passphrase.
func DecryptStream(r io.Reader, w io.Writer, password []byte, concurrency int) (byte, error) {
	// 1. Read Header
	header := make([]byte, 4+1+1+SaltSize+24)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, err
	}

	if string(header[:4]) != MagicHeader {
		return 0, errors.New("invalid file format: missing MAKN magic header")
	}
	if header[4] != Version {
		return 0, errors.New("unsupported maknoon version")
	}
	flags := header[5]

	salt := header[6 : 6+SaltSize]
	baseNonce := header[6+SaltSize:]

	// 2. Derive Key
	key := argon2.IDKey(password, salt, 3, 64*1024, 4, chacha20poly1305.KeySize)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// 3. Setup AEAD
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return 0, err
	}

	// 4. Stream Decrypt Chunks
	return flags, streamDecrypt(r, w, aead, baseNonce, concurrency)
}

// DecryptStreamWithPrivateKey decrypts data from r to w using a Post-Quantum Private Key (Kyber1024).
func DecryptStreamWithPrivateKey(r io.Reader, w io.Writer, privKeyBytes []byte, concurrency int) (byte, error) {
	// 1. Read Header (Fixed part)
	fixedHeader := make([]byte, 4+1+1)
	if _, err := io.ReadFull(r, fixedHeader); err != nil {
		return 0, err
	}

	if string(fixedHeader[:4]) != MagicHeaderAsym {
		return 0, errors.New("invalid file format: missing MAKA magic header")
	}
	if fixedHeader[4] != Version {
		return 0, errors.New("unsupported maknoon version")
	}
	flags := fixedHeader[5]

	// 2. Read KEM Ciphertext
	scheme := kyber1024.Scheme()
	ct := make([]byte, scheme.CiphertextSize())
	if _, err := io.ReadFull(r, ct); err != nil {
		return 0, err
	}

	// 3. Read Base Nonce
	baseNonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(r, baseNonce); err != nil {
		return 0, err
	}

	// 4. Decapsulate Shared Secret
	privKey, err := scheme.UnmarshalBinaryPrivateKey(privKeyBytes)
	if err != nil {
		return 0, fmt.Errorf("invalid private key: %w", err)
	}
	ss, err := scheme.Decapsulate(privKey, ct)
	if err != nil {
		return 0, fmt.Errorf("decapsulation failed: %w", err)
	}
	defer func() {
		for i := range ss {
			ss[i] = 0
		}
	}()

	// 5. Setup AEAD
	aead, err := chacha20poly1305.NewX(ss)
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
		for i := 0; i < 8; i++ {
			nonce[16+i] ^= counterBytes[i]
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
		for i := 0; i < 8; i++ {
			nonce[16+i] ^= counterBytes[i]
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
