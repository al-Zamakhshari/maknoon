package crypto

import (
	"fmt"
	"io"
)

const (
	// ChunkSize is the default size for processing data chunks.
	ChunkSize = 64 * 1024 // 64KB for streaming large files securely
	// MagicHeader is the magic string for symmetric encryption.
	MagicHeader = "MAKN" // Symmetrical (Password)
	// MagicHeaderSym is an alias for MagicHeader for clarity.
	MagicHeaderSym = MagicHeader
	// MagicHeaderAsym is the magic string for asymmetric encryption.
	MagicHeaderAsym = "MAKA" // Asymmetrical (Public Key)

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
	// When set, a threshold byte follows recipientCount in the header.
	FlagThreshold = 1 << 4 // 0x10
)

// ReadHeader parses the file header to extract magic, profile, and flags.
func ReadHeader(r io.Reader, stealth bool) (magic string, profileID byte, flags byte, recipientCount byte, err error) {
	if !stealth {
		m := make([]byte, 4)
		if n, err := io.ReadFull(r, m); err != nil {
			return "", 0, 0, 0, &ErrIO{Path: "stream", Reason: fmt.Sprintf("read only %d bytes: %v", n, err)}
		}
		magic = string(m)

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
