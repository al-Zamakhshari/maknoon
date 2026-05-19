package crypto

import "testing"

// TestRunPOST verifies that all cryptographic Power-On Self-Tests pass.
// This covers ML-DSA-87, ML-KEM-768+X25519, Argon2id, and AES-256-GCM KATs.
func TestRunPOST(t *testing.T) {
	if err := RunPOST(); err != nil {
		t.Errorf("RunPOST failed: %v", err)
	}
}
