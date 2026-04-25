package main

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// runAgentMission defines a standardized sequence of tasks that any Maknoon integration must pass.
func runAgentMission(t *testing.T, ctx context.Context, mcpClient *client.Client) {
	// Mission 1: Discovery
	t.Run("Discovery", func(t *testing.T) {
		tools, err := mcpClient.ListTools(ctx, mcp.ListToolsRequest{})
		if err != nil {
			t.Fatalf("Failed to list tools: %v", err)
		}
		found := false
		for _, tool := range tools.Tools {
			if tool.Name == "gen_passphrase" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Critical tool 'gen_passphrase' not found")
		}
	})

	// Mission 2: Tool Logic
	t.Run("ToolLogic", func(t *testing.T) {
		req := mcp.CallToolRequest{}
		req.Method = "tools/call"
		req.Params.Name = "gen_passphrase"
		req.Params.Arguments = map[string]interface{}{"words": 4.0}

		res, err := mcpClient.CallTool(ctx, req)
		if err != nil {
			t.Fatalf("Tool call failed: %v", err)
		}
		if res.IsError {
			t.Fatalf("Tool returned error: %v", res.Content[0])
		}

		pass := strings.TrimSpace(res.Content[0].(mcp.TextContent).Text)
		if len(strings.Split(pass, "-")) != 4 {
			t.Errorf("Unexpected result from remote gen_passphrase: %q", pass)
		}
	})

	// Mission 3: Local Crypto Cycle (No Network)
	t.Run("LocalCryptoCycle", func(t *testing.T) {
		tmpDir := t.TempDir()
		input := filepath.Join(tmpDir, "secret.txt")
		output := input + ".makn"
		os.WriteFile(input, []byte("mcp-mission-data"), 0644)

		// 1. Generate real keypair for the mission
		kemPub, _, _, _, _, _, err := crypto.GeneratePQKeyPair(1)
		if err != nil {
			t.Fatalf("Failed to generate keypair: %v", err)
		}
		pubPath := filepath.Join(tmpDir, "mission.pub")
		if err := os.WriteFile(pubPath, kemPub, 0644); err != nil {
			t.Fatal(err)
		}

		// 2. Encrypt via MCP using the real key
		encReq := mcp.CallToolRequest{}
		encReq.Method = "tools/call"
		encReq.Params.Name = "encrypt_file"
		encReq.Params.Arguments = map[string]interface{}{
			"input":      input,
			"output":     output,
			"public_key": pubPath,
		}

		res, err := mcpClient.CallTool(ctx, encReq)
		if err != nil || res.IsError {
			t.Fatalf("Remote encryption failed: %v", res.Content)
		}

		// 3. Inspect via MCP
		insReq := mcp.CallToolRequest{}
		insReq.Method = "tools/call"
		insReq.Params.Name = "inspect_file"
		insReq.Params.Arguments = map[string]interface{}{
			"path": output,
		}
		res, err = mcpClient.CallTool(ctx, insReq)
		if err != nil || res.IsError {
			t.Fatalf("Remote inspection failed: %v", res.Content)
		}

		text := res.Content[0].(mcp.TextContent).Text
		if !strings.Contains(text, "MAKA") {
			t.Errorf("Inspection result missing magic bytes: %s", text)
		}
	})
}

func TestTransportSSE(t *testing.T) {
	// 1. Setup SSE Server
	s := createServer()
	ts := httptest.NewUnstartedServer(nil)
	sse := server.NewSSEServer(s, server.WithBaseURL(ts.URL))
	ts.Config.Handler = sse
	ts.Start()
	defer ts.Close()

	// 2. Setup Client
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mcpClient, err := client.NewSSEMCPClient(ts.URL + "/sse")
	if err != nil {
		t.Fatalf("Failed to create SSE client: %v", err)
	}

	if err := mcpClient.Start(ctx); err != nil {
		t.Fatalf("Failed to start SSE client: %v", err)
	}

	// 3. Initialize
	_, err = mcpClient.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: "2024-11-05",
			ClientInfo:      mcp.Implementation{Name: "test-client", Version: "1.0"},
		},
	})
	if err != nil {
		t.Fatalf("Initialization failed: %v", err)
	}

	// 4. Run Universal Mission
	runAgentMission(t, ctx, mcpClient)
}
