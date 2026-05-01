package commands

import (
	"context"
	"encoding/json"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerConfigTools(s *server.MCPServer, engine crypto.MaknoonEngine) {
	s.AddTool(mcp.NewTool("config_list", mcp.WithDescription("Retrieve all active engine configuration")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			conf := engine.GetConfig()
			res, _ := json.Marshal(conf)
			return mcp.NewToolResultText(string(res)), nil
		})

	s.AddTool(mcp.NewTool("config_update", mcp.WithDescription("Update engine configuration")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			conf := engine.GetConfig()

			if val, ok := args["default_identity"].(string); ok {
				conf.DefaultIdentity = val
			}
			if val, ok := args["concurrency"].(float64); ok {
				conf.Performance.Concurrency = int(val)
			}
			if val, ok := args["stealth_mode"].(bool); ok {
				conf.Performance.DefaultStealth = val
			}
			if val, ok := args["nostr_relays"].([]any); ok {
				var relays []string
				for _, v := range val {
					if s, ok := v.(string); ok {
						relays = append(relays, s)
					}
				}
				conf.Nostr.Relays = relays
			}

			err := engine.UpdateConfig(&crypto.EngineContext{Context: ctx}, conf)
			if err != nil {
				return crypto.FormatMCPError(err, "config_update")
			}
			res := crypto.ConfigResult{Status: "success"}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("diagnostic", mcp.WithDescription("Get complete engine and environment diagnostic manifest")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			diag := engine.Diagnostic()
			res, _ := json.Marshal(diag)
			return mcp.NewToolResultText(string(res)), nil
		})

	s.AddTool(mcp.NewTool("audit_export", mcp.WithDescription("Export cryptographic operation history")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			audit, err := engine.AuditExport(&crypto.EngineContext{Context: ctx})
			if err != nil {
				return crypto.FormatMCPError(err, "audit_export")
			}
			res, _ := json.Marshal(audit)
			return mcp.NewToolResultText(string(res)), nil
		})

	s.AddTool(mcp.NewTool("config_init", mcp.WithDescription("Initialize default configuration file")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			conf := crypto.DefaultConfig()
			err := engine.UpdateConfig(&crypto.EngineContext{Context: ctx}, conf)
			if err != nil {
				return crypto.FormatMCPError(err, "config_init")
			}
			res := crypto.ConfigResult{Status: "success", Message: "config initialized"}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})
}
