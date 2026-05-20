package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/reedsolomon"
)

const (
	FragmentMagic = "MAKF"
	VersionV1     = 1
	VersionV2     = 2 // V2 adds SigSize field to header
	VersionV3     = 3 // V3 adds ChunkSize field to header
	headerSizeV1  = 16
	headerSizeV2  = 18
	headerSizeV3  = 22 // V2 + ChunkSize(4)

	// MinChunkSize and MaxChunkSize bound the user-configurable per-shard chunk size.
	MinChunkSize = 4 * 1024        // 4 KB  — minimum for RS to work sensibly
	MaxChunkSize = 4 * 1024 * 1024 // 4 MB  — beyond L3 for most CPUs; diminishing returns
)

// FragmentOptions defines the configuration for data fragmentation.
type FragmentOptions struct {
	DataShards   int
	ParityShards int
	TargetDir    string
	SigningKey   []byte
	OriginalSize int64
	OriginalName string // original filename, written to manifest
	OriginalHash string // hex(sha256) of original file, written to manifest
	// ManifestPath writes the manifest to a separate path instead of <TargetDir>/manifest.json.
	// Use this when distributing shards to cloud storage and keeping the manifest locally
	// (e.g. with rclone: fragment → upload shards only → store manifest in safe location).
	// When empty, manifest is written alongside the shards in TargetDir.
	ManifestPath string
	// ShardChunkSize overrides the per-shard chunk size (default: ChunkSize = 64 KB).
	// Larger values reduce RS encode calls and write syscalls for big files, at the cost
	// of more peak memory (ShardChunkSize × TotalShards). Must be in [MinChunkSize, MaxChunkSize].
	// The value is stored in the V3 shard header so reassembly is always self-describing.
	ShardChunkSize int
}

// effectiveChunkSize returns the validated per-shard chunk size for opts.
func (o *FragmentOptions) effectiveChunkSize() int {
	if o.ShardChunkSize <= 0 {
		return ChunkSize
	}
	if o.ShardChunkSize < MinChunkSize {
		return MinChunkSize
	}
	if o.ShardChunkSize > MaxChunkSize {
		return MaxChunkSize
	}
	return o.ShardChunkSize
}

// FragmentManifest records shard metadata for reassembly and integrity verification.
type FragmentManifest struct {
	Version        int         `json:"version"`
	CreatedAt      time.Time   `json:"created_at"`
	OriginalName   string      `json:"original_name,omitempty"`
	OriginalSize   int64       `json:"original_size"`
	OriginalHash   string      `json:"original_hash,omitempty"` // hex(sha256)
	DataShards     int         `json:"data_shards"`
	ParityShards   int         `json:"parity_shards"`
	TotalShards    int         `json:"total_shards"`
	Signed         bool        `json:"signed"`
	SigSize        int         `json:"sig_size,omitempty"`
	ShardChunkSize int         `json:"shard_chunk_size,omitempty"` // 0 means default (64 KB)
	Shards         []ShardInfo `json:"shards"`
}

// ShardInfo records a single shard's location.
type ShardInfo struct {
	Index    int    `json:"index"`
	Filename string `json:"filename"`
}

// FragmentWriter implements io.Writer by splitting data into erasure-coded shards.
type FragmentWriter struct {
	opts      FragmentOptions
	enc       reedsolomon.Encoder
	writers   []io.WriteCloser
	buffer    []byte
	written   int64
	chunkSize int // effective per-shard chunk size (bytes)
}

func NewFragmentWriter(opts FragmentOptions) (*FragmentWriter, error) {
	totalShards := opts.DataShards + opts.ParityShards
	writers := make([]io.WriteCloser, totalShards)

	if opts.TargetDir != "" {
		safeDir := filepath.Clean(opts.TargetDir)
		// Reject any path that traverses upward.
		if strings.HasPrefix(safeDir, "..") || strings.Contains(safeDir, string(filepath.Separator)+".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("fragment target dir contains path traversal: %q", opts.TargetDir)
		}
		if err := os.MkdirAll(safeDir, 0700); err != nil {
			return nil, err
		}
		for i := 0; i < totalShards; i++ {
			path := filepath.Join(safeDir, fmt.Sprintf("shard_%03d.maknf", i))
			f, err := os.Create(path)
			if err != nil {
				return nil, err
			}
			writers[i] = f
		}
		opts.TargetDir = safeDir

		// Write manifest alongside the shards.
		if err := writeFragmentManifest(opts, writers); err != nil {
			for _, w := range writers {
				_ = w.Close()
			}
			return nil, fmt.Errorf("writing manifest: %w", err)
		}
	}

	return NewFragmentWriterWithWriters(opts, writers)
}

func NewFragmentWriterWithWriters(opts FragmentOptions, writers []io.WriteCloser) (*FragmentWriter, error) {
	enc, err := reedsolomon.New(opts.DataShards, opts.ParityShards)
	if err != nil {
		return nil, err
	}

	// Compute sig size up front so we can store it in the V2 header.
	var sigSize uint16
	if len(opts.SigningKey) > 0 {
		testSig, err := SignData([]byte{0}, opts.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("invalid signing key: %w", err)
		}
		sigSize = uint16(len(testSig))
	}

	effectiveChunk := opts.effectiveChunkSize()
	useV3 := opts.ShardChunkSize > 0 // custom chunk → V3 header so reassembly is self-describing

	totalShards := opts.DataShards + opts.ParityShards
	for i := 0; i < totalShards; i++ {
		if writers[i] == nil {
			continue
		}
		if useV3 {
			// V3 Header: V2(18 bytes) + ChunkSize(4) = 22 bytes
			header := make([]byte, headerSizeV3)
			copy(header[0:4], FragmentMagic)
			header[4] = VersionV3
			header[5] = byte(i)
			header[6] = byte(opts.DataShards)
			header[7] = byte(opts.ParityShards)
			binary.LittleEndian.PutUint64(header[8:16], uint64(opts.OriginalSize))
			binary.LittleEndian.PutUint16(header[16:18], sigSize)
			binary.LittleEndian.PutUint32(header[18:22], uint32(effectiveChunk))
			if _, err := writers[i].Write(header); err != nil {
				return nil, err
			}
		} else {
			// V2 Header: Magic(4) + Ver(1) + ShardIdx(1) + Data(1) + Parity(1) + OrigSize(8) + SigSize(2)
			header := make([]byte, headerSizeV2)
			copy(header[0:4], FragmentMagic)
			header[4] = VersionV2
			header[5] = byte(i)
			header[6] = byte(opts.DataShards)
			header[7] = byte(opts.ParityShards)
			binary.LittleEndian.PutUint64(header[8:16], uint64(opts.OriginalSize))
			binary.LittleEndian.PutUint16(header[16:18], sigSize)
			if _, err := writers[i].Write(header); err != nil {
				return nil, err
			}
		}
	}

	return &FragmentWriter{
		opts:      opts,
		enc:       enc,
		writers:   writers,
		buffer:    make([]byte, 0, effectiveChunk*opts.DataShards),
		chunkSize: effectiveChunk,
	}, nil
}

func (fw *FragmentWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	fw.buffer = append(fw.buffer, p...)

	chunkSize := fw.chunkSize * fw.opts.DataShards
	for len(fw.buffer) >= chunkSize {
		if err := fw.flushChunk(fw.buffer[:chunkSize]); err != nil {
			return 0, err
		}
		fw.buffer = fw.buffer[chunkSize:]
	}

	fw.written += int64(n)
	return n, nil
}

func (fw *FragmentWriter) flushChunk(chunk []byte) error {
	shards, err := fw.enc.Split(chunk)
	if err != nil {
		return err
	}

	if err := fw.enc.Encode(shards); err != nil {
		return err
	}

	for i, shard := range shards {
		if len(fw.opts.SigningKey) > 0 {
			sig, err := SignData(shard, fw.opts.SigningKey)
			if err != nil {
				return err
			}
			if _, err := fw.writers[i].Write(sig); err != nil {
				return err
			}
		}
		if _, err := fw.writers[i].Write(shard); err != nil {
			return err
		}
	}
	return nil
}

func (fw *FragmentWriter) Close() error {
	var closeErr error
	if len(fw.buffer) > 0 {
		if err := fw.flushChunk(fw.buffer); err != nil {
			closeErr = err
		}
		fw.buffer = fw.buffer[:0]
	}

	for _, w := range fw.writers {
		_ = w.Close()
	}
	return closeErr
}

func ReassembleFragments(srcDir string, w io.Writer, authorizedPubKey []byte) error {
	safeDir := filepath.Clean(srcDir)
	// Reject any path containing traversal sequences.
	if strings.HasPrefix(safeDir, "..") || strings.Contains(safeDir, string(filepath.Separator)+".."+string(filepath.Separator)) {
		return fmt.Errorf("source dir contains path traversal: %q", srcDir)
	}

	// Read manifest if present — used for validation and better error messages.
	manifest, _ := ReadFragmentManifest(safeDir)

	files, err := os.ReadDir(safeDir)
	if err != nil {
		return err
	}

	var shardPaths []string
	var dataShards, parityShards int
	var originalSize int64
	var sigSize int
	shardChunkSize := ChunkSize // default; overridden if V3 header found
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".maknf" {
			shardPath := filepath.Join(safeDir, f.Name())
			if dataShards == 0 {
				data, err := os.ReadFile(shardPath)
				if err == nil && len(data) >= headerSizeV1 && string(data[:4]) == FragmentMagic {
					dataShards = int(data[6])
					parityShards = int(data[7])
					originalSize = int64(binary.LittleEndian.Uint64(data[8:16]))
					if data[4] >= VersionV2 && len(data) >= headerSizeV2 {
						sigSize = int(binary.LittleEndian.Uint16(data[16:18]))
					} else if len(authorizedPubKey) > 0 {
						sigSize = 4627 // V1 backward compat: ML-DSA-87 was the only signer
					}
					if data[4] >= VersionV3 && len(data) >= headerSizeV3 {
						shardChunkSize = int(binary.LittleEndian.Uint32(data[18:22]))
					}
				}
			}
			shardPaths = append(shardPaths, shardPath)
		}
	}

	if dataShards == 0 {
		return fmt.Errorf("no valid fragments found in %s", srcDir)
	}

	// Validate against manifest if present.
	if manifest != nil {
		foundCount := len(shardPaths)
		expectedTotal := manifest.DataShards + manifest.ParityShards
		if foundCount < manifest.DataShards {
			return fmt.Errorf("insufficient shards: need at least %d data shards, found %d of %d total",
				manifest.DataShards, foundCount, expectedTotal)
		}
	}

	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return err
	}

	totalShards := dataShards + parityShards
	shardFiles := make([]*os.File, totalShards)
	defer func() {
		for _, f := range shardFiles {
			if f != nil {
				_ = f.Close()
			}
		}
	}()

	for _, p := range shardPaths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		// Read and discard the full header so the file cursor sits at shard data.
		base := make([]byte, headerSizeV1)
		if _, err := io.ReadFull(f, base); err != nil {
			_ = f.Close()
			continue
		}
		if base[4] >= VersionV3 {
			extra := make([]byte, headerSizeV3-headerSizeV1)
			if _, err := io.ReadFull(f, extra); err != nil {
				_ = f.Close()
				continue
			}
		} else if base[4] >= VersionV2 {
			extra := make([]byte, headerSizeV2-headerSizeV1)
			if _, err := io.ReadFull(f, extra); err != nil {
				_ = f.Close()
				continue
			}
		}
		idx := int(base[5])
		if idx < totalShards {
			shardFiles[idx] = f
		}
	}

	remaining := originalSize
	for remaining > 0 {
		shardData := make([][]byte, totalShards)
		var shardLen int

		// Determine shard length for this block (V3 uses header-stored chunk size).
		expectedShardLen := shardChunkSize
		if remaining < int64(shardChunkSize*dataShards) {
			// Last block might be smaller
			expectedShardLen = int((remaining + int64(dataShards) - 1) / int64(dataShards))
		}

		for i := 0; i < totalShards; i++ {
			if shardFiles[i] == nil {
				continue
			}

			if sigSize > 0 {
				sig := make([]byte, sigSize)
				if _, err := io.ReadFull(shardFiles[i], sig); err != nil {
					shardFiles[i] = nil
					continue
				}
				block := make([]byte, expectedShardLen)
				n, err := io.ReadFull(shardFiles[i], block)
				if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
					shardFiles[i] = nil
					continue
				}
				block = block[:n]
				if !VerifySignature(block, sig, authorizedPubKey) {
					return fmt.Errorf("integrity failure in shard %d", i)
				}
				shardData[i] = block
			} else {
				block := make([]byte, expectedShardLen)
				n, err := io.ReadFull(shardFiles[i], block)
				if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
					shardFiles[i] = nil
					continue
				}
				shardData[i] = block[:n]
			}
			if len(shardData[i]) > shardLen {
				shardLen = len(shardData[i])
			}
		}

		for i := 0; i < totalShards; i++ {
			if len(shardData[i]) < shardLen {
				if len(shardData[i]) == 0 {
					shardData[i] = nil
				} else {
					padded := make([]byte, shardLen)
					copy(padded, shardData[i])
					shardData[i] = padded
				}
			}
		}

		if err := enc.Reconstruct(shardData); err != nil {
			return fmt.Errorf("failed to reconstruct block: %w", err)
		}

		writeLen := int(remaining)
		if writeLen > expectedShardLen*dataShards {
			writeLen = expectedShardLen * dataShards
		}

		if err := enc.Join(w, shardData, writeLen); err != nil {
			return err
		}
		remaining -= int64(writeLen)
	}

	return nil
}

// writeFragmentManifest writes manifest.json either to opts.ManifestPath (if set)
// or to <opts.TargetDir>/manifest.json (default). The manifest records all
// metadata needed to verify and reassemble the shards.
func writeFragmentManifest(opts FragmentOptions, writers []io.WriteCloser) error {
	_ = writers // shard file handles already created; manifest references filenames only
	total := opts.DataShards + opts.ParityShards
	shards := make([]ShardInfo, total)
	for i := 0; i < total; i++ {
		shards[i] = ShardInfo{
			Index:    i,
			Filename: fmt.Sprintf("shard_%03d.maknf", i),
		}
	}
	m := FragmentManifest{
		Version:        1,
		CreatedAt:      time.Now().UTC(),
		OriginalName:   opts.OriginalName,
		OriginalSize:   opts.OriginalSize,
		OriginalHash:   opts.OriginalHash,
		DataShards:     opts.DataShards,
		ParityShards:   opts.ParityShards,
		TotalShards:    total,
		Signed:         len(opts.SigningKey) > 0,
		ShardChunkSize: opts.effectiveChunkSize(),
		Shards:         shards,
	}
	// Omit ShardChunkSize from manifest when it's the default (matches legacy behaviour).
	if opts.ShardChunkSize <= 0 {
		m.ShardChunkSize = 0
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	dest := opts.ManifestPath
	if dest == "" {
		if opts.TargetDir == "" {
			return nil
		}
		dest = filepath.Join(opts.TargetDir, "manifest.json")
	}
	return os.WriteFile(dest, data, 0600)
}

// VerifyReassembly checks the SHA-256 of outputPath against the original_hash
// stored in srcDir/manifest.json. Returns nil if they match, an error otherwise.
// If the manifest is absent or has no hash, verification is skipped (returns nil).
func VerifyReassembly(srcDir, outputPath string) error {
	manifest, err := ReadFragmentManifest(srcDir)
	if err != nil {
		return fmt.Errorf("reading manifest: %w", err)
	}
	if manifest == nil || manifest.OriginalHash == "" {
		return nil // nothing to verify against
	}
	got, err := HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("hashing output: %w", err)
	}
	if got != manifest.OriginalHash {
		return fmt.Errorf("integrity check FAILED: output hash %s does not match manifest hash %s", got, manifest.OriginalHash)
	}
	return nil
}

// ReadFragmentManifest reads manifest.json from srcDir if it exists.
// Returns nil without error if the file is absent (backward compat).
func ReadFragmentManifest(srcDir string) (*FragmentManifest, error) {
	path := filepath.Join(filepath.Clean(srcDir), "manifest.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m FragmentManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("invalid manifest.json: %w", err)
	}
	return &m, nil
}

// HashFile computes the SHA-256 of the file at path and returns it as a hex string.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
