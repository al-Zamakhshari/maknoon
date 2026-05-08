package crypto

import (
	"encoding/json"
	"fmt"
)

// ThresholdSignature represents a collection of individual signatures.
type ThresholdSignature struct {
	Signatures [][]byte `json:"signatures"`
}

// Aggregate combines multiple signatures into a single threshold signature object.
func (e *Engine) Aggregate(ectx *EngineContext, signatures [][]byte) ([]byte, error) {
	ts := ThresholdSignature{Signatures: signatures}
	return json.Marshal(ts)
}

// VerifyThreshold verifies that an aggregate signature contains at least 'threshold'
// valid signatures from the provided set of authorized public keys.
func (e *Engine) VerifyThreshold(ectx *EngineContext, data []byte, aggregateSig []byte, authorizedKeys [][]byte, threshold int) (bool, error) {
	var ts ThresholdSignature
	if err := json.Unmarshal(aggregateSig, &ts); err != nil {
		// Fallback: Check if it's a single signature
		for _, pub := range authorizedKeys {
			v, err := e.Verify(ectx, data, aggregateSig, pub)
			if err == nil && v {
				return threshold <= 1, nil
			}
		}
		return false, fmt.Errorf("invalid threshold signature format: %w", err)
	}

	validCount := 0
	matchedKeys := make(map[string]bool)

	// NIST Profile (ProfileV1) uses ML-DSA-87
	mldsaSize := 2592 // mldsa87.PublicKeySize

	for _, sig := range ts.Signatures {
		for _, pub := range authorizedKeys {
			keyID := fmt.Sprintf("%x", pub)
			if matchedKeys[keyID] {
				continue
			}

			// Isolate ML-DSA part if it's a hybrid key
			mldsaPub := pub
			if len(mldsaPub) > mldsaSize {
				mldsaPub = mldsaPub[:mldsaSize]
			}

			v, err := e.Verify(ectx, data, sig, mldsaPub)
			if err == nil && v {
				validCount++
				matchedKeys[keyID] = true
				break
			}
		}
	}

	return validCount >= threshold, nil
}
