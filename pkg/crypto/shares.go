package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Share represents a single Shamir's Secret Sharing shard.
type Share struct {
	Version   byte
	Threshold byte
	Index     byte
	Data      []byte
	Checksum  []byte
}

const (
	ShareVersion = 1
	ChecksumSize = 4 // Use first 4 bytes of SHA-256
)

// GF(2^8) tables
var (
	gfLog [256]byte
	gfExp [512]byte
)

func init() {
	var x byte = 1
	for i := 0; i < 255; i++ {
		gfLog[x] = byte(i)
		gfExp[i] = x
		gfExp[i+255] = x
		x = gfMulStep(x, 0x03)
	}
}

func gfMulStep(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hiBitSet := a&0x80 != 0
		a <<= 1
		if hiBitSet {
			a ^= 0x1b // AES polynomial: x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1
	}
	return p
}

func gfAdd(a, b byte) byte {
	return a ^ b
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[uint16(gfLog[a])+uint16(gfLog[b])]
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("division by zero")
	}
	if a == 0 {
		return 0
	}
	return gfExp[uint16(gfLog[a])+255-uint16(gfLog[b])]
}

// SplitSecret shards a secret into n parts, requiring threshold m to reconstruct.
func SplitSecret(secret []byte, m, n int) ([]Share, error) {
	if m < 2 || m > n || n > 255 {
		return nil, errors.New("invalid m or n: must be 2 <= m <= n <= 255")
	}

	shares := make([]Share, n)
	for i := range shares {
		shares[i] = Share{
			Version:   ShareVersion,
			Threshold: byte(m),
			Index:     byte(i + 1),
			Data:      make([]byte, len(secret)),
		}
	}

	// For each byte of the secret, create a random polynomial
	for j, s := range secret {
		poly := make([]byte, m)
		poly[0] = s // constant term is the secret byte
		for i := 1; i < m; i++ {
			r, _ := rand.Int(rand.Reader, big.NewInt(256))
			poly[i] = byte(r.Int64())
		}

		// Evaluate polynomial at points 1, 2, ..., n
		for i := 1; i <= n; i++ {
			val := poly[0]
			x := byte(i)
			xi := byte(i)
			for k := 1; k < m; k++ {
				val = gfAdd(val, gfMul(poly[k], xi))
				xi = gfMul(xi, x)
			}
			shares[i-1].Data[j] = val
		}
	}

	// Compute checksums
	for i := range shares {
		h := sha256.New()
		h.Write([]byte{shares[i].Version, shares[i].Threshold, shares[i].Index})
		h.Write(shares[i].Data)
		sum := h.Sum(nil)
		shares[i].Checksum = sum[:ChecksumSize]
	}

	return shares, nil
}

// CombineShares reconstructs a secret from at least m shares.
func CombineShares(shares []Share) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}

	m := int(shares[0].Threshold)
	if len(shares) < m {
		return nil, fmt.Errorf("insufficient shares: got %d, need %d", len(shares), m)
	}

	// Validate shares (version, threshold, checksum, and uniqueness)
	secretLen := len(shares[0].Data)
	seenIndices := make(map[byte]bool)
	for _, s := range shares {
		if seenIndices[s.Index] {
			return nil, fmt.Errorf("duplicate share detected: index %d", s.Index)
		}
		seenIndices[s.Index] = true

		if s.Version != ShareVersion {
			return nil, fmt.Errorf("unsupported share version: %d", s.Version)
		}
		if int(s.Threshold) != m {
			return nil, errors.New("inconsistent threshold across shares")
		}
		if len(s.Data) != secretLen {
			return nil, errors.New("inconsistent secret length across shares")
		}
		h := sha256.New()
		h.Write([]byte{s.Version, s.Threshold, s.Index})
		h.Write(s.Data)
		sum := h.Sum(nil)
		if !bytesEqual(sum[:ChecksumSize], s.Checksum) {
			return nil, fmt.Errorf("checksum mismatch for share %d", s.Index)
		}
	}

	secret := make([]byte, secretLen)
	for j := 0; j < secretLen; j++ {
		// Lagrange interpolation at x=0
		var val byte
		for i := 0; i < len(shares); i++ {
			// Compute Lagrange basis polynomial L_i(0)
			basis := byte(1)
			for k := 0; k < len(shares); k++ {
				if i == k {
					continue
				}
				// L_i(0) = product( (0 - x_k) / (x_i - x_k) )
				// In GF(2^8), sub is XOR, so (0 - x_k) is x_k
				num := shares[k].Index
				den := gfAdd(shares[i].Index, shares[k].Index)
				basis = gfMul(basis, gfDiv(num, den))
			}
			val = gfAdd(val, gfMul(shares[i].Data[j], basis))
		}
		secret[j] = val
	}

	return secret, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// FormatShare binary encodes a share.
func (s *Share) Encode() []byte {
	res := make([]byte, 0, 3+len(s.Data)+len(s.Checksum))
	res = append(res, s.Version, s.Threshold, s.Index)
	res = append(res, s.Data...)
	res = append(res, s.Checksum...)
	return res
}

// DecodeShare decodes a binary encoded share.
func DecodeShare(data []byte) (*Share, error) {
	if len(data) < 3+ChecksumSize {
		return nil, errors.New("share data too short")
	}
	s := &Share{
		Version:   data[0],
		Threshold: data[1],
		Index:     data[2],
	}
	dataLen := len(data) - 3 - ChecksumSize
	s.Data = make([]byte, dataLen)
	copy(s.Data, data[3:3+dataLen])
	s.Checksum = make([]byte, ChecksumSize)
	copy(s.Checksum, data[3+dataLen:])
	return s, nil
}

// ToMnemonic converts a share to a human-readable mnemonic string.
func (s *Share) ToMnemonic() string {
	encoded := s.Encode()
	words := make([]string, len(encoded))
	for i, b := range encoded {
		words[i] = WordList[b]
	}
	return strings.Join(words, " ")
}

// FromMnemonic reconstructs a share from a mnemonic string.
func FromMnemonic(mnemonic string) (*Share, error) {
	words := strings.Fields(mnemonic)
	if len(words) < 3+ChecksumSize {
		return nil, errors.New("mnemonic too short")
	}

	wordMap := make(map[string]byte)
	for i, w := range WordList {
		wordMap[w] = byte(i)
	}

	data := make([]byte, len(words))
	for i, w := range words {
		b, ok := wordMap[strings.ToLower(w)]
		if !ok {
			return nil, fmt.Errorf("invalid word in mnemonic: %s", w)
		}
		data[i] = b
	}

	return DecodeShare(data)
}
