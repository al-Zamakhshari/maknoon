package commands

import (
	"context"
	"encoding/json"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerProfilesTools(s *server.MCPServer, engine crypto.MaknoonEngine) {
	s.AddTool(mcp.NewTool("profiles_list", mcp.WithDescription("List all built-in and custom cryptographic profiles")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			conf := engine.GetConfig()

			var res crypto.ProfileListResult
			res.Profiles = append(res.Profiles, crypto.ProfileInfo{Name: "nist", ID: 1, Description: "NIST PQC (Lattice-based)"})
			res.Profiles = append(res.Profiles, crypto.ProfileInfo{Name: "aes", ID: 2, Description: "NIST PQC + AES-GCM"})
			res.Profiles = append(res.Profiles, crypto.ProfileInfo{Name: "conservative", ID: 3, Description: "Non-Lattice PQC"})

			for name, p := range conf.Profiles {
				res.Profiles = append(res.Profiles, crypto.ProfileInfo{Name: name, ID: p.CustomID, Details: p})
			}

			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("profiles_gen", mcp.WithDescription("Generate a new random, validated profile and save it to config")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			name := getString(args, "name", "")
			if name == "" {
				return mcp.NewToolResultError("profile name is required"), nil
			}

			conf := engine.GetConfig()
			usedIDs := make(map[byte]bool)
			usedIDs[1] = true
			usedIDs[2] = true
			usedIDs[3] = true
			for _, p := range conf.Profiles {
				usedIDs[p.CustomID] = true
			}

			var nextID byte = 0
			for i := byte(4); i < 128; i++ {
				if !usedIDs[i] {
					nextID = i
					break
				}
			}

			if nextID == 0 {
				return mcp.NewToolResultError("no available profile IDs"), nil
			}

			dp := engine.GenerateRandomProfile(&crypto.EngineContext{Context: ctx}, nextID)
			if err := engine.ValidateProfile(&crypto.EngineContext{Context: ctx}, dp); err != nil {
				return crypto.FormatMCPError(err, "profiles_gen")
			}

			if err := engine.RegisterProfile(&crypto.EngineContext{Context: ctx}, name, dp); err != nil {
				return crypto.FormatMCPError(err, "profiles_gen")
			}

			res := crypto.ProfileResult{Status: "success", Name: name, ID: nextID, Profile: dp}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("profiles_rm", mcp.WithDescription("Remove a custom profile from config")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			name := getString(args, "name", "")
			if err := engine.RemoveProfile(&crypto.EngineContext{Context: ctx}, name); err != nil {
				return crypto.FormatMCPError(err, "profiles_rm")
			}

			res := crypto.ProfileResult{Status: "success", Removed: name}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})
}
