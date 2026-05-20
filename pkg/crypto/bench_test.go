package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// nopWC is a WriteCloser that discards all data.
type nopWC struct{ io.Writer }

func (nopWC) Close() error { return nil }

// BenchmarkVaultSetGet measures the round-trip cost of storing and retrieving
// a vault entry (includes Argon2id KDF on each operation).
func BenchmarkVaultSetGet(b *testing.B) {
	tmpDir := b.TempDir()
	cfg := DefaultConfig()
	cfg.Paths.VaultsDir = tmpDir

	engine, err := NewEngine(&HumanPolicy{}, nil, cfg, nil, slog.Default())
	if err != nil {
		b.Fatal(err)
	}
	defer engine.Close()

	vaultPath := filepath.Join(tmpDir, "bench.vault")
	pass := []byte("bench-vault-pass")
	ectx := &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}

	entry := &VaultEntry{Service: "benchsvc", Password: SecretBytes("benchpass")}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := engine.VaultSet(ectx, vaultPath, entry, pass, "", true); err != nil {
			b.Fatal(err)
		}
		if _, err := engine.VaultGet(ectx, vaultPath, "benchsvc", pass, ""); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkIdentityKeygen measures ML-KEM-768 + ML-DSA-87 key pair generation.
func BenchmarkIdentityKeygen(b *testing.B) {
	tmpDir := b.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	cfg := DefaultConfig()
	engine, err := NewEngine(&HumanPolicy{}, nil, cfg, nil, slog.Default())
	if err != nil {
		b.Fatal(err)
	}
	defer engine.Close()

	ectx := &EngineContext{Context: context.Background(), Policy: &HumanPolicy{}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := "benchid"
		if _, err := engine.CreateIdentity(ectx, name, nil, "", true, "nist"); err != nil {
			b.Fatal(err)
		}
		// Delete to allow re-creation next iteration
		engine.IdentityDelete(ectx, name)
	}
}

// BenchmarkSignVerify measures ML-DSA-87 sign + verify on a 1KB payload.
func BenchmarkSignVerify(b *testing.B) {
	_, _, spub, spriv, err := GeneratePQKeyPair(1)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := SignData(data, spriv)
		if err != nil {
			b.Fatal(err)
		}
		if !VerifySignature(data, sig, spub) {
			b.Fatal("verify failed")
		}
	}
}

// BenchmarkPQKeyPairGeneration isolates ML-KEM-768 + ML-DSA-87 key generation.
// This is the pure cryptographic cost; BenchmarkIdentityKeygen measures the
// higher-level CreateIdentity which folds in disk I/O.
func BenchmarkPQKeyPairGeneration(b *testing.B) {
	profiles := []struct {
		label string
		id    byte
	}{
		{"Profile1_NIST", 1},         // ML-KEM-768 + X25519 / ML-DSA-87
		{"Profile3_Conservative", 3}, // FrodoKEM-640 / SLH-DSA
	}
	for _, p := range profiles {
		p := p
		b.Run(p.label, func(b *testing.B) {
			if p.id == 3 {
				b.Skip("FrodoKEM-640 keygen is intentionally slow — run without -short to include")
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, _, _, err := GeneratePQKeyPair(p.id); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkPublicKeyEncryption measures the ML-KEM-768 + X25519 hybrid handshake
// plus AES-256-GCM encryption. Tested across recipient counts and payload sizes
// to expose KEM overhead relative to data volume.
func BenchmarkPublicKeyEncryption(b *testing.B) {
	sizes := []struct {
		label string
		bytes int
	}{
		{"1MB", 1 * 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
	}
	recipientCounts := []int{1, 3}

	for _, s := range sizes {
		data := make([]byte, s.bytes)
		if _, err := rand.Read(data); err != nil {
			b.Fatal(err)
		}
		for _, n := range recipientCounts {
			pubKeys := make([][]byte, n)
			for i := range pubKeys {
				kemPub, _, _, _, err := GeneratePQKeyPair(1)
				if err != nil {
					b.Fatal(err)
				}
				pubKeys[i] = kemPub
			}
			label := s.label + "_" + string(rune('0'+n)) + "recipients"
			b.Run(label, func(b *testing.B) {
				b.SetBytes(int64(s.bytes))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := EncryptStreamWithPublicKeys(bytes.NewReader(data), io.Discard, pubKeys, FlagNone, 0, 0); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkFragmentEncode measures Reed-Solomon encoding throughput using in-memory
// discard writers to isolate RS encode cost from disk I/O. Tests different shard
// configs and chunk sizes introduced in the V3 shard header.
func BenchmarkFragmentEncode(b *testing.B) {
	configs := []struct {
		label     string
		data      int
		parity    int
		chunkSize int // bytes; 0 = default 64 KB
	}{
		{"5+3_default64KB", 5, 3, 0},
		{"5+3_256KB", 5, 3, 256 * 1024},
		{"10+4_default64KB", 10, 4, 0},
	}

	payload := make([]byte, 10*1024*1024) // 10 MB
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}

	for _, cfg := range configs {
		cfg := cfg
		b.Run(cfg.label, func(b *testing.B) {
			total := cfg.data + cfg.parity
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				writers := make([]io.WriteCloser, total)
				for j := range writers {
					writers[j] = nopWC{io.Discard}
				}
				opts := FragmentOptions{
					DataShards:     cfg.data,
					ParityShards:   cfg.parity,
					ShardChunkSize: cfg.chunkSize,
					OriginalSize:   int64(len(payload)),
				}
				fw, err := NewFragmentWriterWithWriters(opts, writers)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := io.Copy(fw, bytes.NewReader(payload)); err != nil {
					b.Fatal(err)
				}
				if err := fw.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkKDFVariants compares Argon2id at different time parameter values.
func BenchmarkKDFVariants(b *testing.B) {
	password := []byte("kdf-bench-password")
	salt := make([]byte, 16)

	for _, argonTime := range []uint32{1, 2, 3} {
		argonTime := argonTime
		b.Run("ArgonTime"+string(rune('0'+argonTime)), func(b *testing.B) {
			p := &ProfileV1{
				ArgonTime: argonTime,
				ArgonMem:  64 * 1024,
				ArgonThrd: 4,
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = p.DeriveKey(password, salt)
			}
		})
	}
}

// BenchmarkEncryptionSmallFiles exposes the KDF "cliff" for files smaller than 64KB.
// At these sizes, the 26ms Argon2id overhead dominates actual encryption time.
func BenchmarkEncryptionSmallFiles(b *testing.B) {
	password := []byte("small-file-bench")
	sizes := []struct {
		label string
		size  int
	}{
		{"1KB", 1024},
		{"4KB", 4 * 1024},
		{"16KB", 16 * 1024},
		{"64KB", 64 * 1024},
		{"256KB", 256 * 1024},
	}

	for _, s := range sizes {
		data := make([]byte, s.size)
		b.Run(s.label, func(b *testing.B) {
			b.SetBytes(int64(s.size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := EncryptStream(bytes.NewReader(data), io.Discard, password, FlagNone, 1, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
