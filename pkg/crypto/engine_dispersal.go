package crypto

import (
	"io"
)

// ReassembleFragments reconstructs a file from its fragments.
func (e *Engine) ReassembleFragments(srcDir string, w io.Writer, authorizedPubKey []byte) error {
	return ReassembleFragments(srcDir, w, authorizedPubKey)
}
