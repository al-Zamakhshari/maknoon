package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerConfigTools(s *server.MCPServer, engine crypto.MaknoonEngine) {
	s.AddTool(mcp.NewTool("config_list",
		mcp.WithDescription("Retrieve all active engine configuration"),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		conf := engine.GetConfig()
		res, _ := json.Marshal(conf)
		return mcp.NewToolResultText(string(res)), nil
	})

	s.AddTool(mcp.NewTool("config_update",
		mcp.WithDescription("Update engine configuration"),
		mcp.WithString("default_identity", mcp.Description("Default identity name to use for operations")),
		mcp.WithNumber("profile_id", mcp.Description("Default cryptographic profile ID (1=NIST, 3=Conservative)")),
		mcp.WithNumber("concurrency", mcp.Description("Number of parallel encryption workers")),
		mcp.WithBoolean("stealth_mode", mcp.Description("Enable fingerprint-resistant headers by default")),
		mcp.WithString("nostr_relays", mcp.Description("Comma-separated list of Nostr relay URLs")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		conf := engine.GetConfig()

		if val := getString(args, "default_identity", ""); val != "" {
			conf.DefaultIdentity = val
		}
		if val := getInt(args, "profile_id", 0); val != 0 {
			conf.Performance.DefaultProfile = byte(val)
		}
		if val := getInt(args, "concurrency", 0); val != 0 {
			conf.Performance.Concurrency = val
		}
		if val, ok := args["stealth_mode"].(bool); ok {
			conf.Performance.DefaultStealth = val
		}
		// Accept nostr_relays as either a comma-separated string or a JSON array
		if relays := getStringSlice(args, "nostr_relays"); len(relays) > 0 {
			conf.Nostr.Relays = relays
		} else if relayStr := getString(args, "nostr_relays", ""); relayStr != "" {
			var relays []string
			for _, r := range strings.Split(relayStr, ",") {
				if r = strings.TrimSpace(r); r != "" {
					relays = append(relays, r)
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

	s.AddTool(mcp.NewTool("diagnostic",
		mcp.WithDescription("Get a complete engine and environment diagnostic manifest"),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		diag := engine.Diagnostic()
		res, _ := json.Marshal(diag)
		return mcp.NewToolResultText(string(res)), nil
	})

	s.AddTool(mcp.NewTool("audit_export",
		mcp.WithDescription("Export the cryptographic operation history (hash-chained, ML-DSA-87 signed log)"),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		audit, err := engine.AuditExport(&crypto.EngineContext{Context: ctx})
		if err != nil {
			return crypto.FormatMCPError(err, "audit_export")
		}
		res, _ := json.Marshal(audit)
		return mcp.NewToolResultText(string(res)), nil
	})

	s.AddTool(mcp.NewTool("audit_verify",
		mcp.WithDescription("Verify the hash-chain integrity of the audit log to detect tampering"),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		conf := engine.GetConfig()
		logPath := conf.Audit.LogFile
		if logPath == "" {
			return mcp.NewToolResultError(`{"error":"audit log path not configured"}`), nil
		}

		entries, err := engine.AuditExport(&crypto.EngineContext{Context: ctx})
		if err != nil {
			return crypto.FormatMCPError(err, "audit_verify")
		}

		chainErr := crypto.VerifyChain(logPath)
		res := map[string]any{
			"valid":           chainErr == nil,
			"entries_checked": len(entries),
			"log_path":        logPath,
		}
		if chainErr != nil {
			res["error"] = chainErr.Error()
			msg := chainErr.Error()
			if idx := strings.Index(msg, "entry "); idx >= 0 {
				var brokenAt int
				fmt.Sscanf(msg[idx+6:], "%d", &brokenAt)
				res["first_broken_at"] = brokenAt
			}
		}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("config_init",
		mcp.WithDescription("Initialize default configuration file"),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
