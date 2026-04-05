package crypto

const (
	ChunkSize       = 64 * 1024 // 64KB for streaming large files securely
	MagicHeader     = "MAKN"    // Symmetrical (Password)
	MagicHeaderAsym = "MAKA"    // Asymmetrical (Public Key)
	Version         = byte(1)
	SaltSize        = 32

	// Flags (Bitmask)
	FlagNone     = byte(0)
	FlagArchive  = 1 << 0 // 0x01
	FlagCompress = 1 << 1 // 0x02
)
