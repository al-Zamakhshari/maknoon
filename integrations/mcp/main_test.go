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
	"time"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestMCPServerTools(t *testing.T) {
	// Build the maknoon binary for the MCP server to use
	tmpDir := t.TempDir()
	maknoonPath := filepath.Join(tmpDir, "maknoon")
	buildCmd := exec.Command("go", "build", "-o", maknoonPath, "../../cmd/maknoon")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build maknoon for tests: %v", err)
	}

	// Set environment for the server to find the binary and a mock home
	os.Setenv("MAKNOON_BINARY", maknoonPath)
	os.Setenv("HOME", tmpDir)
	defer os.Unsetenv("MAKNOON_BINARY")

	s := createServer()
	ctx := context.Background()

	// Generate a test identity for all subtests
	keygenCmd := exec.Command(maknoonPath, "keygen", "-o", "test-id", "--no-password")
	keygenCmd.Env = append(os.Environ(), "MAKNOON_JSON=1")
	if err := keygenCmd.Run(); err != nil {
		t.Fatalf("Failed to generate test identity: %v", err)
	}

	t.Run("Tool List", func(t *testing.T) {
		tools := s.ListTools()
		if len(tools) == 0 {
			t.Fatal("Expected at least one tool, got zero")
		}
		expectedTools := []string{
			"vault_get", "vault_set", "encrypt_file", "decrypt_file",
			"gen_password", "gen_passphrase", "inspect_file", "identity_active",
			"profiles_list", "profiles_gen",
		}
		for _, name := range expectedTools {
			if _, ok := tools[name]; !ok {
				t.Errorf("Missing expected tool: %s", name)
			}
		}
	})

	t.Run("Credential Generation", func(t *testing.T) {
		// Test Password Generation
		passReq := json.RawMessage(`{
			"jsonrpc": "2.0",
			"id": "3",
			"method": "tools/call",
			"params": {
				"name": "gen_password",
				"arguments": {"length": 16}
			}
		}`)
		res := s.HandleMessage(ctx, passReq)
		resRaw, _ := json.Marshal(res)
		if !strings.Contains(string(resRaw), "password") {
			t.Errorf("Password generation failed. Result: %s", string(resRaw))
		}

		// Test Passphrase Generation
		phraseReq := json.RawMessage(`{
			"jsonrpc": "2.0",
			"id": "4",
			"method": "tools/call",
			"params": {
				"name": "gen_passphrase",
				"arguments": {"words": 3, "separator": "."}
			}
		}`)
		res = s.HandleMessage(ctx, phraseReq)
		resRaw, _ = json.Marshal(res)
		if !strings.Contains(string(resRaw), "passphrase") {
			t.Errorf("Passphrase generation failed. Result: %s", string(resRaw))
		}
	})

	t.Run("File Lifecycle (Encrypt/Inspect/Decrypt)", func(t *testing.T) {
		// 1. Setup Data & Identity
		inputPath := filepath.Join(tmpDir, "secret.txt")
		_ = os.WriteFile(inputPath, []byte("hello-mcp"), 0644)
		outputPath := inputPath + ".makn"

		pubKeyPath := filepath.Join(tmpDir, ".maknoon", "keys", "test-id.kem.pub")
		privKeyPath := filepath.Join(tmpDir, ".maknoon", "keys", "test-id.kem.key")

		// 2. Encrypt
		encReq := json.RawMessage(fmt.Sprintf(`{
			"jsonrpc": "2.0",
			"id": "5",
			"method": "tools/call",
			"params": {
				"name": "encrypt_file",
				"arguments": {
					"input": "%s",
					"output": "%s",
					"public_key": "%s"
				}
			}
		}`, inputPath, outputPath, pubKeyPath))

		res := s.HandleMessage(ctx, encReq)
		resRaw, _ := json.Marshal(res)
		if !strings.Contains(string(resRaw), "success") {
			t.Fatalf("Encryption tool failed. Result: %s", string(resRaw))
		}

		// 3. Inspect
		insReq := json.RawMessage(fmt.Sprintf(`{
			"jsonrpc": "2.0",
			"id": "6",
			"method": "tools/call",
			"params": {
				"name": "inspect_file",
				"arguments": {
					"path": "%s"
				}
			}
		}`, outputPath))
		res = s.HandleMessage(ctx, insReq)
		resRaw, _ = json.Marshal(res)
		// We refactored info to return raw header data
		if !strings.Contains(string(resRaw), "MAKA") {
			t.Errorf("File inspection failed. Result: %s", string(resRaw))
		}

		// 4. Decrypt
		decPath := inputPath + ".restored"
		decReq := json.RawMessage(fmt.Sprintf(`{
			"jsonrpc": "2.0",
			"id": "7",
			"method": "tools/call",
			"params": {
				"name": "decrypt_file",
				"arguments": {
					"input": "%s",
					"output": "%s",
					"private_key": "%s"
				}
			}
		}`, outputPath, decPath, privKeyPath))
		res = s.HandleMessage(ctx, decReq)
		resRaw, _ = json.Marshal(res)
		if !strings.Contains(string(resRaw), "success") {
			t.Errorf("Decryption tool failed. Result: %s", string(resRaw))
		}

		// Verify content
		restored, _ := os.ReadFile(decPath)
		if string(restored) != "hello-mcp" {
			t.Errorf("Restored content mismatch. Got: %s", string(restored))
		}
	})

	t.Run("Identity Active Success", func(t *testing.T) {
		req := json.RawMessage(`{
			"jsonrpc": "2.0",
			"id": "1",
			"method": "tools/call",
			"params": {
				"name": "identity_active",
				"arguments": {}
			}
		}`)

		res := s.HandleMessage(ctx, req)
		resRaw, _ := json.Marshal(res)
		if !strings.Contains(string(resRaw), "test-id.kem.pub") {
			t.Errorf("Identity discovery failed. Result: %s", string(resRaw))
		}
	})

	t.Run("P2P Directory Send (Tool Logic)", func(t *testing.T) {
		// Create a directory to send
		srcDir := filepath.Join(tmpDir, "mcp_src_dir")
		os.Mkdir(srcDir, 0755)
		os.WriteFile(filepath.Join(srcDir, "hello.txt"), []byte("mcp-p2p"), 0644)

		// Note: We don't actually run the full P2P transfer here as it blocks
		// and requires public relays, which can flake in CI.
		// Instead, we verify the tool is registered and the handler is reachable.

		req := json.RawMessage(fmt.Sprintf(`{
			"jsonrpc": "2.0",
			"id": "8",
			"method": "tools/call",
			"params": {
				"name": "send_file",
				"arguments": {
					"path": "%s"
				}
			}
		}`, srcDir))

		// We expect this to fail or timeout in CI if it tries to hit a real relay,
		// but we can check if it gets past the 'directories not supported' check.
		// Since we fixed directory support, it should now proceed to 'Opening wormhole'.
		// We use a short context to avoid hanging.
		timeoutCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		res := s.HandleMessage(timeoutCtx, req)
		resRaw, _ := json.Marshal(res)

		// If it says 'Opening wormhole' or 'Preparing to send', we know it accepted the directory.
		if strings.Contains(string(resRaw), "directories are not yet supported") {
			t.Errorf("MCP send_file still rejecting directories")
		}
	})

	t.Run("P2P Text Send (Tool Logic)", func(t *testing.T) {
		req := json.RawMessage(`{
			"jsonrpc": "2.0",
			"id": "9",
			"method": "tools/call",
			"params": {
				"name": "send_file",
				"arguments": {
					"text": "mcp-text-payload"
				}
			}
		}`)

		timeoutCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		res := s.HandleMessage(timeoutCtx, req)
		resRaw, _ := json.Marshal(res)

		if strings.Contains(string(resRaw), "either 'path' or 'text' must be provided") {
			t.Errorf("MCP send_file failed to recognize 'text' argument")
		}
	})

	t.Run("Vault Get Error (Missing Master Key)", func(t *testing.T) {
		req := json.RawMessage(`{
			"jsonrpc": "2.0",
			"id": "2",
			"method": "tools/call",
			"params": {
				"name": "vault_get",
				"arguments": {"service": "nonexistent"}
			}
		}`)

		res := s.HandleMessage(ctx, req)
		resRaw, _ := json.Marshal(res)
		if !strings.Contains(string(resRaw), "passphrase required") {
			t.Errorf("Expected master key error, got: %s", string(resRaw))
		}
	})

	t.Run("Start Chat Tool", func(t *testing.T) {
		if testing.Short() || os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Skip("skipping network test in short mode or CI")
		}
		req := json.RawMessage(`{
			"jsonrpc": "2.0",
			"id": "10",
			"method": "tools/call",
			"params": {
				"name": "start_chat",
				"arguments": {}
			}
		}`)

		res := s.HandleMessage(ctx, req)
		resRaw, _ := json.Marshal(res)

		if !strings.Contains(string(resRaw), "established") || !strings.Contains(string(resRaw), "status") {
			t.Errorf("Start chat tool failed. Result: %s", string(resRaw))
		}
	})

	t.Run("Identity Publish Local", func(t *testing.T) {
		req := json.RawMessage(`{
			"jsonrpc": "2.0",
			"id": "11",
			"method": "tools/call",
			"params": {
				"name": "identity_publish",
				"arguments": {
					"handle": "@mcp",
					"name": "test-id",
					"local": true
				}
			}
		}`)

		res := s.HandleMessage(ctx, req)
		resRaw, _ := json.Marshal(res)
		if !strings.Contains(string(resRaw), "success") {
			t.Errorf("Identity publish local failed. Result: %s", string(resRaw))
		}
	})

	t.Run("Profiles Management", func(t *testing.T) {
		// 1. Generate a new profile
		genReq := json.RawMessage(`{
			"jsonrpc": "2.0",
			"id": "12",
			"method": "tools/call",
			"params": {
				"name": "profiles_gen",
				"arguments": {"name": "mcp-test-profile"}
			}
		}`)
		res := s.HandleMessage(ctx, genReq)
		resRaw, _ := json.Marshal(res)
		// The tool outputs the PROFILE JSON directly if successful.
		if !strings.Contains(string(resRaw), "kdf_iterations") {
			t.Fatalf("Profiles generation tool failed. Result: %s", string(resRaw))
		}

		// 2. List profiles
		listReq := json.RawMessage(`{
			"jsonrpc": "2.0",
			"id": "13",
			"method": "tools/call",
			"params": {
				"name": "profiles_list",
				"arguments": {}
			}
		}`)
		res = s.HandleMessage(ctx, listReq)
		resRaw, _ = json.Marshal(res)
		// NOTE: In Agent Mode, profiles are ephemeral and NOT saved to config.
		// So we expect 'nist' (default) but NOT 'mcp-test-profile'.
		if !strings.Contains(string(resRaw), "nist") {
			t.Errorf("Profiles list tool failed to show default profile. Result: %s", string(resRaw))
		}
		if strings.Contains(string(resRaw), "mcp-test-profile") {
			t.Errorf("Profiles list tool unexpectedly showed ephemeral profile (should not be saved in agent mode). Result: %s", string(resRaw))
		}
	})
}
