package crypto

import "io"

// EncryptThreshold writes a K-of-N threshold-encrypted file to w.
// r is the plaintext source; pubKeys is the N recipient KEM public keys;
// threshold is K (2 ≤ K ≤ N ≤ 255). Any K key holders can cooperate to
// decrypt; fewer than K cannot reconstruct the FEK.
func (e *Engine) EncryptThreshold(ectx *EngineContext, r io.Reader, w io.Writer,
	pubKeys [][]byte, threshold int, opts Options) error {

	var profileID byte
	if opts.ProfileID != nil {
		profileID = *opts.ProfileID
	}
	return EncryptStreamThreshold(r, w, pubKeys, threshold, FlagNone, 0, profileID, ectx)
}

// CollectThresholdShare reads the threshold-encrypted file from r and extracts
// this recipient's Shamir share using privKey. The returned ThresholdShare
// should be serialised with ThresholdShareToJSON and stored until K shares are
// available for CombineAndDecrypt.
func (e *Engine) CollectThresholdShare(ectx *EngineContext, r io.Reader,
	privKey []byte, profileID byte) (*ThresholdShare, error) {

	return DecryptThresholdCollectShare(r, privKey, profileID)
}

// CombineAndDecrypt combines at least K ThresholdShares to recover the FEK
// and decrypts src, writing plaintext to w (or to outPath when w is nil).
func (e *Engine) CombineAndDecrypt(ectx *EngineContext, src io.Reader, w io.Writer,
	outPath string, shares []*ThresholdShare) error {

	return DecryptThresholdCombine(src, w, outPath, shares, ectx)
}
