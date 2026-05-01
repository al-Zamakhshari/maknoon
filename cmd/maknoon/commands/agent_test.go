package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAgentIdentityFlow(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)

	if err := InitEngine(); err != nil {
		t.Fatalf("InitEngine failed: %v", err)
	}
	defer func() {
		if GlobalContext.Engine != nil {
			GlobalContext.Engine.Close()
		}
	}()

	os.Setenv("MAKNOON_JSON", "1")
	defer os.Unsetenv("MAKNOON_JSON")
	SetJSONOutput(true)
	defer SetJSONOutput(false)

	// 1. Keygen
	gen := KeygenCmd()
	gen.SetArgs([]string{"-o", "agent_id", "--no-password", "--quiet"})
	if err := gen.Execute(); err != nil {
		t.Fatalf("Keygen failed: %v", err)
	}

	// 2. Publish Local
	pub := IdentityCmd()
	pub.SetArgs([]string{"publish", "@agent", "--name", "agent_id", "--local"})
	var pubOut bytes.Buffer
	GlobalContext.JSONWriter = &pubOut
	if err := pub.Execute(); err != nil {
		t.Fatalf("Identity publish failed: %v", err)
	}

	var pubRes map[string]interface{}
	if err := json.Unmarshal(pubOut.Bytes(), &pubRes); err != nil {
		t.Fatalf("Failed to parse publish JSON (output: %s): %v", pubOut.String(), err)
	}
	if pubRes["status"] != "success" {
		t.Errorf("Unexpected publish result: %v", pubRes)
	}

	// 3. Encrypt using handle
	inputFile := filepath.Join(tmpDir, "secret.txt")
	os.WriteFile(inputFile, []byte("agent test data"), 0644)

	enc := EncryptCmd()
	enc.SetArgs([]string{inputFile, "-o", inputFile + ".makn", "-p", "@agent", "--quiet"})
	if err := enc.Execute(); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 4. Decrypt
	dec := DecryptCmd()
	dec.SetArgs([]string{inputFile + ".makn", "-k", filepath.Join(tmpDir, ".maknoon", "keys", "agent_id.kem.key"), "-o", filepath.Join(tmpDir, "restored.txt"), "--quiet"})
	if err := dec.Execute(); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	restored, _ := os.ReadFile(filepath.Join(tmpDir, "restored.txt"))
	if string(restored) != "agent test data" {
		t.Errorf("Restored data mismatch: %s", restored)
	}
}

func TestAgentShardingFlow(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)

	if err := InitEngine(); err != nil {
		t.Fatalf("InitEngine failed: %v", err)
	}
	defer func() {
		if GlobalContext.Engine != nil {
			GlobalContext.Engine.Close()
		}
	}()

	os.Setenv("MAKNOON_JSON", "1")
	defer os.Unsetenv("MAKNOON_JSON")
	SetJSONOutput(true)
	defer SetJSONOutput(false)

	// 1. Keygen
	gen := KeygenCmd()
	gen.SetArgs([]string{"-o", "shard_id", "--no-password", "--quiet"})
	gen.Execute()

	// 2. Split
	split := IdentityCmd()
	split.SetArgs([]string{"split", "shard_id"})
	var splitOut bytes.Buffer
	GlobalContext.JSONWriter = &splitOut
	if err := split.Execute(); err != nil {
		t.Fatalf("Identity split failed: %v", err)
	}

	var splitRes struct {
		Status string   `json:"status"`
		Shares []string `json:"shares"`
	}
	if err := json.Unmarshal(splitOut.Bytes(), &splitRes); err != nil {
		t.Fatalf("Failed to parse split JSON (output: %s): %v", splitOut.String(), err)
	}

	if len(splitRes.Shares) != 3 {
		t.Fatalf("Expected 3 shares, got %d", len(splitRes.Shares))
	}

	// 3. Combine (Use 2 shares)
	combine := IdentityCmd()
	args := append([]string{"combine"}, splitRes.Shares[0], splitRes.Shares[1], "--output", "recovered_id", "--no-password")
	combine.SetArgs(args)
	var combineOut bytes.Buffer
	GlobalContext.JSONWriter = &combineOut
	if err := combine.Execute(); err != nil {
		t.Fatalf("Identity combine failed: %v", err)
	}

	// 4. Verify recovered keys exist
	recoveredPub := filepath.Join(tmpDir, ".maknoon", "keys", "recovered_id.nostr.pub")
	if _, err := os.Stat(recoveredPub); err != nil {
		t.Errorf("Recovered Nostr pubkey missing: %v", err)
	}
}
