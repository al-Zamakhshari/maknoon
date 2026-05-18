package crypto

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/reedsolomon"
)

const (
	FragmentMagic = "MAKF"
	VersionV1     = 1
)

// FragmentOptions defines the configuration for data fragmentation.
type FragmentOptions struct {
	DataShards   int
	ParityShards int
	TargetDir    string
	SigningKey   []byte
	OriginalSize int64
}

// FragmentWriter implements io.Writer by splitting data into erasure-coded shards.
type FragmentWriter struct {
	opts    FragmentOptions
	enc     reedsolomon.Encoder
	writers []io.WriteCloser
	buffer  []byte
	written int64
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
	}

	return NewFragmentWriterWithWriters(opts, writers)
}

func NewFragmentWriterWithWriters(opts FragmentOptions, writers []io.WriteCloser) (*FragmentWriter, error) {
	enc, err := reedsolomon.New(opts.DataShards, opts.ParityShards)
	if err != nil {
		return nil, err
	}

	totalShards := opts.DataShards + opts.ParityShards
	for i := 0; i < totalShards; i++ {
		if writers[i] == nil {
			continue
		}
		// V1 Header: Magic(4) + Ver(1) + ShardIdx(1) + Data(1) + Parity(1) + OrigSize(8)
		header := make([]byte, 16)
		copy(header[0:4], FragmentMagic)
		header[4] = VersionV1
		header[5] = byte(i)
		header[6] = byte(opts.DataShards)
		header[7] = byte(opts.ParityShards)
		binary.LittleEndian.PutUint64(header[8:16], uint64(opts.OriginalSize))

		if _, err := writers[i].Write(header); err != nil {
			return nil, err
		}
	}

	return &FragmentWriter{
		opts:    opts,
		enc:     enc,
		writers: writers,
		buffer:  make([]byte, 0, ChunkSize*opts.DataShards),
	}, nil
}

func (fw *FragmentWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	fw.buffer = append(fw.buffer, p...)

	chunkSize := ChunkSize * fw.opts.DataShards
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
	if len(fw.buffer) > 0 {
		shards, err := fw.enc.Split(fw.buffer)
		if err == nil {
			if err := fw.enc.Encode(shards); err == nil {
				for i, shard := range shards {
					if len(fw.opts.SigningKey) > 0 {
						sig, _ := SignData(shard, fw.opts.SigningKey)
						_, _ = fw.writers[i].Write(sig)
					}
					_, _ = fw.writers[i].Write(shard)
				}
			}
		}
	}

	for _, w := range fw.writers {
		_ = w.Close()
	}
	return nil
}

func ReassembleFragments(srcDir string, w io.Writer, authorizedPubKey []byte) error {
	safeDir := filepath.Clean(srcDir)
	// Reject any path containing traversal sequences.
	if strings.HasPrefix(safeDir, "..") || strings.Contains(safeDir, string(filepath.Separator)+".."+string(filepath.Separator)) {
		return fmt.Errorf("source dir contains path traversal: %q", srcDir)
	}
	files, err := os.ReadDir(safeDir)
	if err != nil {
		return err
	}

	var shardPaths []string
	var dataShards, parityShards int
	var originalSize int64
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".maknf" {
			shardPath := filepath.Join(safeDir, f.Name())
			if dataShards == 0 {
				data, err := os.ReadFile(shardPath)
				if err == nil && len(data) >= 16 && string(data[:4]) == FragmentMagic {
					dataShards = int(data[6])
					parityShards = int(data[7])
					originalSize = int64(binary.LittleEndian.Uint64(data[8:16]))
				}
			}
			shardPaths = append(shardPaths, shardPath)
		}
	}

	if dataShards == 0 {
		return fmt.Errorf("no valid fragments found in %s", srcDir)
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
		header := make([]byte, 16)
		if _, err := io.ReadFull(f, header); err != nil {
			_ = f.Close()
			continue
		}
		idx := int(header[5])
		if idx < totalShards {
			shardFiles[idx] = f
		}
	}

	sigSize := 0
	if len(authorizedPubKey) > 0 {
		sigSize = 4627
	}

	remaining := originalSize
	for remaining > 0 {
		shardData := make([][]byte, totalShards)
		var shardLen int

		// Determine shard length for this block
		expectedShardLen := ChunkSize
		if remaining < int64(ChunkSize*dataShards) {
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
