package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgenticIntegrationStress(t *testing.T) {
	// Setup: Build and Prepare
	tmpDir := t.TempDir()
	maknoonPath := filepath.Join(tmpDir, "maknoon")
	buildCmd := exec.Command("go", "build", "-o", maknoonPath, "../../cmd/maknoon")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build maknoon: %v", err)
	}

	os.Setenv("MAKNOON_BINARY", maknoonPath)
	os.Setenv("HOME", tmpDir)
	os.Setenv("MAKNOON_AGENT_MODE", "1")
	defer os.Unsetenv("MAKNOON_BINARY")

	s := createServer()
	ctx := context.Background()

	// MISSION 1: Provisioning & Discovery
	t.Run("Mission: Provisioning", func(t *testing.T) {
		// Agent generates its own identity
		req := json.RawMessage(`{
			"jsonrpc": "2.0",
			"id": "m1",
			"method": "tools/call",
			"params": {
				"name": "gen_passphrase",
				"arguments": {"words": 4}
			}
		}`)
		res := s.HandleMessage(ctx, req)
		var passRes struct {
			Result struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		raw, _ := json.Marshal(res)
		json.Unmarshal(raw, &passRes)
		
		passphrase := strings.TrimSpace(passRes.Result.Content[0].Text)
		if passphrase == "" {
			t.Fatal("Agent failed to generate passphrase")
		}

		// Save passphrase for next steps
		os.Setenv("MAKNOON_PASSPHRASE", passphrase)

		// Create identity
		keygenCmd := exec.Command(maknoonPath, "keygen", "-o", "agent-id", "-s", passphrase)
		if err := keygenCmd.Run(); err != nil {
			t.Fatalf("Agent identity generation failed: %v", err)
		}
	})

	// MISSION 2: Vault Governance
	t.Run("Mission: Vault Governance", func(t *testing.T) {
		// Store secret
		setReq := json.RawMessage(`{
			"jsonrpc": "2.0",
			"id": "m2a",
			"method": "tools/call",
			"params": {
				"name": "vault_set",
				"arguments": {
					"service": "aws-prod-key",
					"user": "admin",
					"password": "secret-payload-123"
				}
			}
		}`)
		s.HandleMessage(ctx, setReq)

		// Retrieve secret
		getReq := json.RawMessage(`{
			"jsonrpc": "2.0",
			"id": "m2b",
			"method": "tools/call",
			"params": {
				"name": "vault_get",
				"arguments": {"service": "aws-prod-key"}
			}
		}`)
		res := s.HandleMessage(ctx, getReq)
		raw, _ := json.Marshal(res)
		if !strings.Contains(string(raw), "secret-payload-123") {
			t.Errorf("Agent failed to retrieve stored secret. Result: %s", string(raw))
		}
	})

	// MISSION 3: Sandbox Escape Verification
	t.Run("Mission: Sandbox Integrity", func(t *testing.T) {
		// Attempt to encrypt a file outside the workspace (Security Violation)
		badPath := "/etc/passwd"
		if _, err := os.Stat(badPath); err != nil {
			// Fallback for CI environments
			badPath = filepath.Join(os.TempDir(), "..", "forbidden.txt")
			os.WriteFile(badPath, []byte("forbidden"), 0644)
		}

		escReq := json.RawMessage(fmt.Sprintf(`{
			"jsonrpc": "2.0",
			"id": "m3",
			"method": "tools/call",
			"params": {
				"name": "encrypt_file",
				"arguments": {
					"input": "%s",
					"output": "escaped.makn"
				}
			}
		}`, badPath))

		res := s.HandleMessage(ctx, escReq)
		raw, _ := json.Marshal(res)
		if !strings.Contains(string(raw), "security_policy_violation") {
			t.Errorf("Agent was able to bypass sandbox! Result: %s", string(raw))
		}
	})

	// MISSION 4: Config Hardening
	t.Run("Mission: Config Hardening", func(t *testing.T) {
		// Agents have NO tools for config modification, but let's verify profile persistence rejection
		profReq := json.RawMessage(`{
			"jsonrpc": "2.0",
			"id": "m4",
			"method": "tools/call",
			"params": {
				"name": "profiles_gen",
				"arguments": {"name": "malicious-profile"}
			}
		}`)
		res := s.HandleMessage(ctx, profReq)
		raw, _ := json.Marshal(res)
		if !strings.Contains(string(raw), "could not save to config") {
			t.Errorf("Agent was able to modify global config! Result: %s", string(raw))
		}
	})
}
