package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptStream symmetrically encrypts data from r to w using a passphrase.
func EncryptStream(r io.Reader, w io.Writer, password []byte, flags byte, concurrency int) error {
	// 1. Generate random Salt for Argon2id
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	// 2. Derive Key: Argon2id (Time: 3, Mem: 64MB, Threads: 4)
	key := argon2.IDKey(password, salt, 3, 64*1024, 4, chacha20poly1305.KeySize)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// 3. Setup XChaCha20-Poly1305 & Random Base Nonce
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return err
	}

	// 4. Write Header: Magic (4) | Version (1) | Flags (1) | Salt (32) | BaseNonce (24)
	if _, err := w.Write([]byte(MagicHeader)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{Version, flags}); err != nil {
		return err
	}
	if _, err := w.Write(salt); err != nil {
		return err
	}
	if _, err := w.Write(baseNonce); err != nil {
		return err
	}

	// 5. Stream Encrypt Chunks
	return streamEncrypt(r, w, aead, baseNonce, concurrency)
}

// EncryptStreamWithPublicKey encrypts data from r to w using a Post-Quantum Public Key (Kyber1024).
func EncryptStreamWithPublicKey(r io.Reader, w io.Writer, pubKeyBytes []byte, flags byte, concurrency int) error {
	// 1. Unpack Public Key
	scheme := kyber1024.Scheme()
	pubKey, err := scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// 2. Encapsulate Shared Secret
	ct, ss, err := scheme.Encapsulate(pubKey)
	if err != nil {
		return fmt.Errorf("failed to encapsulate: %w", err)
	}
	defer func() {
		for i := range ss {
			ss[i] = 0
		}
	}()

	// 3. Setup AEAD with Shared Secret (32 bytes)
	aead, err := chacha20poly1305.NewX(ss)
	if err != nil {
		return err
	}
	baseNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, baseNonce); err != nil {
		return err
	}

	// 4. Write Header: Magic (4) | Version (1) | Flags (1) | KEM Ciphertext (1568) | BaseNonce (24)
	if _, err := w.Write([]byte(MagicHeaderAsym)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{Version, flags}); err != nil {
		return err
	}
	if _, err := w.Write(ct); err != nil {
		return err
	}
	if _, err := w.Write(baseNonce); err != nil {
		return err
	}

	// 5. Stream Encrypt Chunks
	return streamEncrypt(r, w, aead, baseNonce, concurrency)
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

// Internal helper to avoid code duplication
func streamEncrypt(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte, concurrency int) error {
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}

	// If concurrency is 1, use the sequential path for simplicity
	if concurrency == 1 {
		return streamEncryptSequential(r, w, aead, baseNonce)
	}

	jobs := make(chan encryptJob, concurrency*2)
	results := make(chan encryptResult, concurrency*2)
	var wg sync.WaitGroup

	// Workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go encryptionWorker(&wg, jobs, results, aead, baseNonce)
	}

	// Closer
	go func() {
		wg.Wait()
		close(results)
	}()

	// Reader
	errChan := make(chan error, 1)
	go encryptionReader(r, jobs, errChan)

	// Writer (Sequencer)
	return encryptionSequencer(w, results, errChan)
}

func encryptionWorker(wg *sync.WaitGroup, jobs <-chan encryptJob, results chan<- encryptResult, aead cipher.AEAD, baseNonce []byte) {
	defer wg.Done()
	for job := range jobs {
		nonce := make([]byte, aead.NonceSize())
		copy(nonce, baseNonce)
		counterBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(counterBytes, job.index)
		for i := 0; i < 8; i++ {
			nonce[16+i] ^= counterBytes[i]
		}

		ciphertext := aead.Seal(nil, nonce, job.data, nil)
		results <- encryptResult{index: job.index, data: ciphertext}
	}
}

func encryptionReader(r io.Reader, jobs chan<- encryptJob, errChan chan<- error) {
	defer close(jobs)
	chunkIndex := uint64(0)
	for {
		buf := make([]byte, ChunkSize)
		n, err := r.Read(buf)
		if n > 0 {
			jobs <- encryptJob{index: chunkIndex, data: buf[:n]}
			chunkIndex++
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

func encryptionSequencer(w io.Writer, results <-chan encryptResult, errChan <-chan error) error {
	nextIndex := uint64(0)
	pending := make(map[uint64][]byte)
	for {
		select {
		case err := <-errChan:
			return err
		case res, ok := <-results:
			if !ok {
				if len(pending) > 0 {
					return fmt.Errorf("encryption pipeline failed: missing chunks")
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

				if err := writeChunk(w, data); err != nil {
					return err
				}

				delete(pending, nextIndex)
				nextIndex++
			}
		}
	}
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

func streamEncryptSequential(r io.Reader, w io.Writer, aead cipher.AEAD, baseNonce []byte) error {
	buf := make([]byte, ChunkSize)
	chunkIndex := uint64(0)
	nonce := make([]byte, aead.NonceSize())

	for {
		n, err := r.Read(buf)
		if n > 0 {
			copy(nonce, baseNonce)
			counterBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(counterBytes, chunkIndex)
			for i := 0; i < 8; i++ {
				nonce[16+i] ^= counterBytes[i]
			}

			ciphertext := aead.Seal(nil, nonce, buf[:n], nil)

			if err := writeChunk(w, ciphertext); err != nil {
				return err
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
