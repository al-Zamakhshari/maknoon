package crypto

import (
	"io"
)

// --- Engine Wrappers ---

// ReassembleFragments reconstructs a file from its fragments.
func (e *Engine) ReassembleFragments(srcDir string, w io.Writer, authorizedPubKey []byte) error {
	return e.Crypto.ReassembleFragments(srcDir, w, authorizedPubKey)
}

// --- CryptoService Implementation ---

// ReassembleFragments reconstructs a file from its fragments.
func (s *CryptoService) ReassembleFragments(srcDir string, w io.Writer, authorizedPubKey []byte) error {
	return ReassembleFragments(srcDir, w, authorizedPubKey)
}
