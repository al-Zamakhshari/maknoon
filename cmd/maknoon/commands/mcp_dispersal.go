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

func registerDispersalTools(s *server.MCPServer, engine crypto.MaknoonEngine) {
	s.AddTool(mcp.NewTool("fragment_file",
		mcp.WithDescription("Split a file into erasure-coded shards (RAID-for-Privacy). Any data_shards-of-total shards reconstruct the original."),
		mcp.WithString("input", mcp.Required(), mcp.Description("Path to the file to fragment")),
		mcp.WithString("output_dir", mcp.Description("Directory to write shards into (default: <input>_fragments)")),
		mcp.WithNumber("data_shards", mcp.Description("Number of data shards (default: 5)")),
		mcp.WithNumber("parity_shards", mcp.Description("Number of parity shards for redundancy (default: 3)")),
		mcp.WithString("sign_with", mcp.Description("Path to ML-DSA private key to sign each shard block")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		inputPath := getString(args, "input", "")
		if inputPath == "" {
			return mcp.NewToolResultError("input is required"), nil
		}

		outDir := getString(args, "output_dir", inputPath+"_fragments")
		dataShards := getInt(args, "data_shards", 5)
		parityShards := getInt(args, "parity_shards", 3)
		sigKeyPath := getString(args, "sign_with", "")

		var sigKey []byte
		if sigKeyPath != "" {
			passRaw := viper.GetString("passphrase")
			resolved := engine.ResolveKeyPath(&crypto.EngineContext{Context: ctx}, sigKeyPath, "")
			var err error
			sigKey, err = engine.LoadPrivateKey(&crypto.EngineContext{Context: ctx}, resolved, []byte(passRaw), "", true)
			if err != nil {
				return crypto.FormatMCPError(err, "fragment_file")
			}
			defer crypto.SafeClear(sigKey)
		}

		opts := crypto.FragmentOptions{
			DataShards:   dataShards,
			ParityShards: parityShards,
			TargetDir:    outDir,
			SigningKey:   sigKey,
		}

		if err := engine.FragmentFile(&crypto.EngineContext{Context: ctx}, inputPath, opts); err != nil {
			return crypto.FormatMCPError(err, "fragment_file")
		}

		entries, _ := os.ReadDir(outDir)
		res := map[string]any{
			"status":        "success",
			"output_dir":    outDir,
			"data_shards":   dataShards,
			"parity_shards": parityShards,
			"total_shards":  dataShards + parityShards,
			"shard_count":   len(entries),
		}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("reassemble_file",
		mcp.WithDescription("Reconstruct a file from erasure-coded shards. Requires at least data_shards shards to be present."),
		mcp.WithString("src_dir", mcp.Required(), mcp.Description("Directory containing the .maknf shard files")),
		mcp.WithString("output", mcp.Required(), mcp.Description("Path to write the reconstructed file")),
		mcp.WithString("authorized_key", mcp.Description("Path to ML-DSA public key to verify shard integrity (optional)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		srcDir := getString(args, "src_dir", "")
		outputPath := getString(args, "output", "")
		if srcDir == "" || outputPath == "" {
			return mcp.NewToolResultError("src_dir and output are required"), nil
		}

		var authKey []byte
		if keyPath := getString(args, "authorized_key", ""); keyPath != "" {
			var err error
			authKey, err = os.ReadFile(keyPath)
			if err != nil {
				return crypto.FormatMCPError(err, "reassemble_file")
			}
		}

		if err := engine.ReassembleToPath(&crypto.EngineContext{Context: ctx}, srcDir, outputPath, authKey); err != nil {
			return crypto.FormatMCPError(err, "reassemble_file")
		}

		fi, _ := os.Stat(outputPath)
		res := map[string]any{
			"status": "success",
			"output": outputPath,
		}
		if fi != nil {
			res["size_bytes"] = fi.Size()
		}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})
}
