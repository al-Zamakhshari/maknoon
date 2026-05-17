package crypto

import (
	"context"
	"testing"
)

func TestThresholdSignatures(t *testing.T) {
	conf := DefaultConfig()
	policy := &HumanPolicy{}
	e, err := NewEngine(policy, nil, conf, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	ectx := &EngineContext{Context: context.Background(), Policy: policy}

	data := []byte("Mission Critical Data: Alpha-9-Zeta")

	// 1. Generate 3 Identities

	_, _, kp1_sigPub, kp1_sigPriv, _ := GeneratePQKeyPair(1)
	_, _, kp2_sigPub, kp2_sigPriv, _ := GeneratePQKeyPair(1)
	_, _, kp3_sigPub, kp3_sigPriv, _ := GeneratePQKeyPair(1)

	// 2. Sign with each
	sig1, err := e.Sign(ectx, data, kp1_sigPriv)
	if err != nil {
		t.Fatalf("Sign 1 failed: %v", err)
	}
	sig2, err := e.Sign(ectx, data, kp2_sigPriv)
	if err != nil {
		t.Fatalf("Sign 2 failed: %v", err)
	}
	sig3, err := e.Sign(ectx, data, kp3_sigPriv)
	if err != nil {
		t.Fatalf("Sign 3 failed: %v", err)
	}

	// 3. Aggregate
	agg, err := e.Aggregate(ectx, [][]byte{sig1, sig2, sig3})
	if err != nil {
		t.Fatalf("Aggregate failed: %v", err)
	}

	authorizedPubs := [][]byte{kp1_sigPub, kp2_sigPub, kp3_sigPub}

	// 4. Verify Thresholds
	t.Run("Threshold_3_of_3", func(t *testing.T) {
		valid, err := e.VerifyThreshold(ectx, data, agg, authorizedPubs, 3)
		if err != nil || !valid {
			t.Errorf("Expected 3-of-3 to be valid, got valid=%v, err=%v", valid, err)
		}
	})

	t.Run("Threshold_2_of_3", func(t *testing.T) {
		valid, err := e.VerifyThreshold(ectx, data, agg, authorizedPubs, 2)
		if err != nil || !valid {
			t.Errorf("Expected 2-of-3 to be valid, got valid=%v, err=%v", valid, err)
		}
	})

	t.Run("Threshold_Exceeded", func(t *testing.T) {
		valid, err := e.VerifyThreshold(ectx, data, agg, authorizedPubs, 4)
		if valid {
			t.Error("Expected 4-of-3 to be invalid")
		}
		if err != nil {
			t.Logf("Got expected error for invalid threshold: %v", err)
		}
	})

	t.Run("Partial_Aggregation", func(t *testing.T) {
		agg2, _ := e.Aggregate(ectx, [][]byte{sig1, sig2})
		valid, _ := e.VerifyThreshold(ectx, data, agg2, authorizedPubs, 3)
		if valid {
			t.Error("Expected 2-sig aggregate to fail 3-threshold check")
		}
		valid, _ = e.VerifyThreshold(ectx, data, agg2, authorizedPubs, 2)
		if !valid {
			t.Error("Expected 2-sig aggregate to pass 2-threshold check")
		}
	})

	t.Run("Unauthorized_Key", func(t *testing.T) {
		_, _, kp4_sigPub, _, _ := GeneratePQKeyPair(1)
		valid, _ := e.VerifyThreshold(ectx, data, agg, [][]byte{kp4_sigPub}, 1)
		if valid {
			t.Error("Expected verification with unauthorized key to fail")
		}
	})
}
