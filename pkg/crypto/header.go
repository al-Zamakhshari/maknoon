package crypto

const (
	// ChunkSize is the default size for processing data chunks.
	ChunkSize = 64 * 1024 // 64KB for streaming large files securely
	// MagicHeader is the magic string for symmetric encryption.
	MagicHeader = "MAKN" // Symmetrical (Password)
	// MagicHeaderAsym is the magic string for asymmetric encryption.
	MagicHeaderAsym = "MAKA" // Asymmetrical (Public Key)
	// Version is the current version of the Maknoon file format.
	Version = byte(1)
	// SaltSize is the size of the salt used for key derivation.
	SaltSize = 32

	// FlagNone represents no flags set.
	FlagNone = byte(0)
	// FlagArchive indicates the file is a TAR archive.
	FlagArchive = 1 << 0 // 0x01
	// FlagCompress indicates the file is Zstd compressed.
	FlagCompress = 1 << 1 // 0x02
)
