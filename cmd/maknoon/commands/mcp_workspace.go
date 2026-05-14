package commands

import (
	"context"
	"encoding/json"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerWorkspaceTools(s *server.MCPServer, engine crypto.MaknoonEngine) {
	s.AddTool(mcp.NewTool("workspace_create", mcp.WithDescription("Create an ephemeral, isolated sandbox directory for sensitive data")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			name := getString(args, "name", "session")

			path, err := engine.WorkspaceCreate(&crypto.EngineContext{Context: ctx}, name)
			if err != nil {
				return crypto.FormatMCPError(err, "workspace_create")
			}

			res := map[string]string{
				"status": "success",
				"path":   path,
				"note":   "This workspace is ephemeral and should be shredded after use.",
			}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("workspace_shred", mcp.WithDescription("Securely delete and zeroize an ephemeral workspace")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			path := getString(args, "path", "")

			err := engine.WorkspaceShred(&crypto.EngineContext{Context: ctx}, path)
			if err != nil {
				return crypto.FormatMCPError(err, "workspace_shred")
			}

			res := map[string]string{
				"status": "success",
				"path":   path,
			}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})
}
