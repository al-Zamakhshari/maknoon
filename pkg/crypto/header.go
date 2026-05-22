package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// ChunkSize is the default size for processing data chunks.
	ChunkSize = 64 * 1024 // 64KB for streaming large files securely

	// --- V1 magic bytes ---

	// MagicHeader is the magic string for symmetric encryption (V1).
	MagicHeader = "MAKN" // Symmetrical (Password)
	// MagicHeaderSym is an alias for MagicHeader for clarity.
	MagicHeaderSym = MagicHeader
	// MagicHeaderAsym is the magic string for asymmetric encryption (V1).
	MagicHeaderAsym = "MAKA" // Asymmetrical (Public Key)

	// --- V2 magic bytes ---

	// MagicHeaderV2Sym is the magic string for V2 symmetric encryption.
	// Layout: MAK2(4) | FormatVersion(1) | ProfileID(1) | Flags(2 LE) |
	//         ExtLen(2 LE) | [TLV]* | SaltLen(1) | Salt | BaseNonce |
	//         HeaderMAC(32) | [Chunks]* | 0x00000000
	MagicHeaderV2Sym = "MAK2"
	// MagicHeaderV2Asym is the magic string for V2 asymmetric encryption.
	// Layout: MAK3(4) | FormatVersion(1) | ProfileID(1) | Flags(2 LE) |
	//         RecipientCount(1) | ExtLen(2 LE) | [TLV]* |
	//         [Hash(4)+Block]*N | [Sig]? | BaseNonce | HeaderMAC(32) |
	//         [Chunks]* | 0x00000000
	MagicHeaderV2Asym = "MAK3"

	// FormatVersionV2Sym is the FormatVersion byte written after MAK2.
	FormatVersionV2Sym byte = 2
	// FormatVersionV2Asym is the FormatVersion byte written after MAK3.
	FormatVersionV2Asym byte = 3

	// HeaderMACSize is the size in bytes of the header MAC field in V2 files.
	HeaderMACSize = 32

	// --- V1 flag bits (1-byte flags field) ---

	// FlagNone represents no flags set.
	FlagNone = byte(0)
	// FlagArchive indicates the file is a TAR archive.
	FlagArchive = 1 << 0 // 0x01
	// FlagCompress indicates the file is Zstd compressed.
	FlagCompress = 1 << 1 // 0x02
	// FlagSigned indicates the file header includes an integrated signature.
	FlagSigned = 1 << 2 // 0x04
	// FlagStealth indicates the magic bytes are omitted for fingerprint resistance.
	FlagStealth = 1 << 3 // 0x08
	// FlagThreshold indicates K-of-N threshold decryption is required.
	// When set (V1 only), a threshold byte follows recipientCount in the header.
	FlagThreshold = 1 << 4 // 0x10

	// --- V2 TLV tags ---

	// TLVTagThreshold carries [K uint8, N uint8] for threshold encryption.
	TLVTagThreshold uint16 = 0x0001
	// TLVTagChunkSize carries a uint32 LE chunk size in bytes.
	TLVTagChunkSize uint16 = 0x0002
	// TLVTagPlainLen carries a uint64 LE original plaintext byte count (0=unknown).
	TLVTagPlainLen uint16 = 0x0003
	// TLVTagSenderID carries the first 4 bytes of SHA256(senderPubKey).
	TLVTagSenderID uint16 = 0x0004
	// TLVTagFilename carries the original filename as a UTF-8 string.
	TLVTagFilename uint16 = 0x0005
	// TLVTagContentType carries an ASCII MIME type string.
	TLVTagContentType uint16 = 0x0006
	// TLVTagAAD carries arbitrary authenticated-but-unencrypted bytes.
	TLVTagAAD uint16 = 0x0007
	// TLVTagExpires carries a uint64 LE Unix timestamp (advisory expiry).
	TLVTagExpires uint16 = 0x0008
	// TLVTagPadding carries a uint32 LE count of padding bytes appended
	// to the plaintext (stripped by the decoder).
	TLVTagPadding uint16 = 0x0009
	// TLVTagKDFParams carries explicit Argon2id parameters:
	// [Time uint8, MemMB uint32 LE, Threads uint8].
	TLVTagKDFParams uint16 = 0x000A
)

// TLVEntry is a single tag-length-value extension field in a V2 header.
// Unknown tags are silently skipped on read (forward compatibility).
type TLVEntry struct {
	Tag   uint16
	Value []byte
}

// EncodeTLVs serialises a slice of TLVEntry values into the V2 TLV wire format:
// [Tag(2 LE) | Length(2 LE) | Value(Length)]*
func EncodeTLVs(entries []TLVEntry) []byte {
	if len(entries) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, e := range entries {
		var tagBuf [4]byte
		binary.LittleEndian.PutUint16(tagBuf[0:2], e.Tag)
		binary.LittleEndian.PutUint16(tagBuf[2:4], uint16(len(e.Value)))
		buf.Write(tagBuf[:])
		buf.Write(e.Value)
	}
	return buf.Bytes()
}

// DecodeTLVs deserialises a V2 TLV block. Unknown tags are preserved so
// higher-level code can inspect them; invalid trailing bytes are silently ignored.
func DecodeTLVs(b []byte) []TLVEntry {
	var out []TLVEntry
	for len(b) >= 4 {
		tag := binary.LittleEndian.Uint16(b[0:2])
		length := binary.LittleEndian.Uint16(b[2:4])
		b = b[4:]
		if int(length) > len(b) {
			break // truncated — stop
		}
		val := make([]byte, length)
		copy(val, b[:length])
		out = append(out, TLVEntry{Tag: tag, Value: val})
		b = b[length:]
	}
	return out
}

// FindTLV returns the value of the first TLV entry with the given tag,
// or nil if not found.
func FindTLV(tlvs []TLVEntry, tag uint16) []byte {
	for _, e := range tlvs {
		if e.Tag == tag {
			return e.Value
		}
	}
	return nil
}

// ComputeHeaderMAC computes the V2 header integrity MAC:
// HMAC-SHA256(key=fek, data=headerBytes). This provides key commitment —
// the header is authenticated under the same key used to encrypt the payload.
func ComputeHeaderMAC(fek, headerBytes []byte) []byte {
	h := hmac.New(sha256.New, fek)
	h.Write(headerBytes)
	return h.Sum(nil) // 32 bytes
}

// VerifyHeaderMAC checks that mac == ComputeHeaderMAC(fek, headerBytes).
// Returns false if verification fails (wrong key or tampered header).
func VerifyHeaderMAC(fek, headerBytes, mac []byte) bool {
	expected := ComputeHeaderMAC(fek, headerBytes)
	return hmac.Equal(expected, mac)
}

// writeChunkTerminator writes the 4-byte V2 stream terminator (0x00000000).
// In the V2 format, a chunk length of 0 signals clean end-of-stream.
// Valid AES-GCM ciphertext is always ≥ 17 bytes, so 0 is unambiguous.
func writeChunkTerminator(w io.Writer) error {
	var zero [4]byte
	_, err := w.Write(zero[:])
	return err
}

// ReadHeader parses a V1 file header (MAKN/MAKA magic) to extract magic, profile, and flags.
// For V2 files (MAK2/MAK3), the returned magic is "MAK2" or "MAK3" and the caller must
// use the V2-specific decode path (DecryptStreamV2 / DecryptStreamAsymV2).
// The flags field is always the V1 1-byte value; V2 callers must read the 2-byte uint16 flags separately.
func ReadHeader(r io.Reader, stealth bool) (magic string, profileID byte, flags byte, recipientCount byte, err error) {
	if !stealth {
		m := make([]byte, 4)
		if n, err := io.ReadFull(r, m); err != nil {
			return "", 0, 0, 0, &ErrIO{Path: "stream", Reason: fmt.Sprintf("read only %d bytes: %v", n, err)}
		}
		magic = string(m)

		// V2 magic: route to the appropriate V2 decoder — return early so the
		// caller can dispatch without reading further (V2 headers are different).
		if magic == MagicHeaderV2Sym || magic == MagicHeaderV2Asym {
			return magic, 0, 0, 0, nil
		}

		if magic != MagicHeaderSym && magic != MagicHeaderAsym {
			return magic, 0, 0, 0, &ErrFormat{Reason: fmt.Sprintf("invalid magic header: %s", magic)}
		}

		meta := make([]byte, 2)
		if _, err = io.ReadFull(r, meta); err != nil {
			return magic, 0, 0, 0, &ErrIO{Path: "stream", Reason: err.Error()}
		}
		profileID = meta[0]
		flags = meta[1]
	} else {
		// In stealth mode, we expect profileID and flags directly (2 bytes)
		meta := make([]byte, 2)
		if _, err = io.ReadFull(r, meta); err != nil {
			return "", 0, 0, 0, &ErrIO{Path: "stream", Reason: err.Error()}
		}
		profileID = meta[0]
		flags = meta[1]
	}

	if magic == MagicHeaderAsym {
		count := make([]byte, 1)
		if _, err = io.ReadFull(r, count); err != nil {
			return magic, profileID, flags, 0, &ErrIO{Path: "stream", Reason: err.Error()}
		}
		recipientCount = count[0]
	}

	return
}
