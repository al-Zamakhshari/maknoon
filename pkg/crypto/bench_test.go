package crypto

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

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
