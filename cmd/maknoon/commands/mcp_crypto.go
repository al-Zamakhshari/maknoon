package commands

import (
	"context"
	"encoding/json"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"
)

func registerCryptoTools(s *server.MCPServer, engine crypto.MaknoonEngine) {
	s.AddTool(mcp.NewTool("encrypt_file", mcp.WithDescription("Encrypt a file")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			opts := crypto.Options{ProfileID: 1}

			passRaw := viper.GetString("passphrase")
			if passRaw != "" {
				opts.Passphrase = []byte(passRaw)
			}

			if pk := getString(args, "public_key", ""); pk != "" {
				m := crypto.NewIdentityManager()
				if res := m.ResolveKeyPath(pk, ""); res != "" {
					data, err := os.ReadFile(res)
					if err == nil {
						opts.Recipients = append(opts.Recipients, data)
					}
				}
			}

			input := getString(args, "input", "")
			output := getString(args, "output", "")

			in, err := os.Open(input)
			if err != nil {
				return crypto.FormatMCPError(err, "encrypt_file")
			}
			defer in.Close()

			out, err := os.Create(output)
			if err != nil {
				return crypto.FormatMCPError(err, "encrypt_file")
			}
			defer out.Close()

			_, err = engine.Protect(nil, "", in, out, opts)
			if err != nil {
				return crypto.FormatMCPError(err, "encrypt_file")
			}
			return mcp.NewToolResultText(`{"status":"success"}`), nil
		})

	s.AddTool(mcp.NewTool("inspect_file", mcp.WithDescription("Analyze header metadata")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			in, _ := os.Open(getString(args, "path", ""))
			info, err := engine.Inspect(nil, in)
			if err != nil {
				return crypto.FormatMCPError(err, "inspect_file")
			}
			res, _ := json.Marshal(info)
			return mcp.NewToolResultText(string(res)), nil
		})

	s.AddTool(mcp.NewTool("gen_passphrase", mcp.WithDescription("Generate a secure mnemonic")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			words, _ := args["words"].(float64)
			pass, err := engine.GeneratePassphrase(nil, int(words), "-")
			if err != nil {
				return crypto.FormatMCPError(err, "gen_passphrase")
			}
			return mcp.NewToolResultText(pass), nil
		})
}
