package commands

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"
)

func registerCryptoTools(s *server.MCPServer, engine crypto.MaknoonEngine) {
	s.AddTool(mcp.NewTool("encrypt_file", mcp.WithDescription("Encrypt a file")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			opts := crypto.Options{}

			passRaw := viper.GetString("passphrase")
			if passRaw != "" {
				opts.Passphrase = crypto.SecretBytes(passRaw)
			}

			if pk := getString(args, "public_key", ""); pk != "" {
				data, err := engine.ResolvePublicKey(&crypto.EngineContext{Context: ctx}, pk, false)
				if err == nil {
					opts.Recipients = append(opts.Recipients, data)
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

			res, err := engine.Protect(&crypto.EngineContext{Context: ctx}, "", in, out, opts)
			if err != nil {
				return crypto.FormatMCPError(err, "encrypt_file")
			}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("decrypt_file", mcp.WithDescription("Decrypt a .makn file")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			input := getString(args, "input", "")
			output := getString(args, "output", "")
			keyPath := getString(args, "private_key", "")
			senderKeyPath := getString(args, "sender_key", "")

			opts := crypto.Options{}
			passRaw := viper.GetString("passphrase")

			// Handle Private Key if provided
			if keyPath != "" {
				resolved := engine.ResolveKeyPath(&crypto.EngineContext{Context: ctx}, keyPath, "")
				priv, err := engine.LoadPrivateKey(&crypto.EngineContext{Context: ctx}, resolved, []byte(passRaw), "", true)
				if err != nil {
					return crypto.FormatMCPError(err, "decrypt_file")
				}
				opts.LocalPrivateKey = priv
				defer crypto.SafeClear(priv)
			} else if passRaw != "" {
				opts.Passphrase = crypto.SecretBytes(passRaw)
			}

			// Handle Sender Key for verification
			if senderKeyPath != "" {
				sk, err := engine.ResolvePublicKey(&crypto.EngineContext{Context: ctx}, senderKeyPath, false)
				if err != nil {
					return crypto.FormatMCPError(err, "decrypt_file")
				}
				opts.PublicKey = sk
			}

			in, err := os.Open(input)
			if err != nil {
				return crypto.FormatMCPError(err, "decrypt_file")
			}
			defer in.Close()

			res, err := engine.Unprotect(&crypto.EngineContext{Context: ctx}, in, nil, output, opts)
			if err != nil {
				return crypto.FormatMCPError(err, "decrypt_file")
			}

			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("sign_file", mcp.WithDescription("Sign a file using an ML-DSA private key")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			path := getString(args, "path", "")
			keyPath := getString(args, "private_key", "")
			output := getString(args, "output", path+".sig")

			data, err := os.ReadFile(path)
			if err != nil {
				return crypto.FormatMCPError(err, "sign_file")
			}

			passRaw := viper.GetString("passphrase")
			resolved := engine.ResolveKeyPath(&crypto.EngineContext{Context: ctx}, keyPath, "")
			priv, err := engine.LoadPrivateKey(&crypto.EngineContext{Context: ctx}, resolved, []byte(passRaw), "", true)
			if err != nil {
				return crypto.FormatMCPError(err, "sign_file")
			}
			defer crypto.SafeClear(priv)

			sig, err := engine.Sign(&crypto.EngineContext{Context: ctx}, data, priv)
			if err != nil {
				return crypto.FormatMCPError(err, "sign_file")
			}

			if err := os.WriteFile(output, sig, 0600); err != nil {
				return crypto.FormatMCPError(err, "sign_file")
			}

			res := crypto.SignResult{Status: "success", SignaturePath: output}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("verify_file", mcp.WithDescription("Verify a file's signature (supports threshold verification)")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			path := getString(args, "path", "")
			sigPath := getString(args, "signature", "")
			pubKeyList := getString(args, "public_keys", "")
			threshold, _ := args["threshold"].(float64)

			data, err := os.ReadFile(path)
			if err != nil {
				return crypto.FormatMCPError(err, "verify_file")
			}
			sig, err := os.ReadFile(sigPath)
			if err != nil {
				return crypto.FormatMCPError(err, "verify_file")
			}

			var pubKeys [][]byte
			if pubKeyList != "" {
				parts := strings.Split(pubKeyList, ",")
				for _, p := range parts {
					pk, err := engine.ResolvePublicKey(&crypto.EngineContext{Context: ctx}, strings.TrimSpace(p), false)
					if err != nil {
						return crypto.FormatMCPError(err, "verify_file")
					}
					pubKeys = append(pubKeys, pk)
				}
			} else if pkStr := getString(args, "public_key", ""); pkStr != "" {
				pk, err := engine.ResolvePublicKey(&crypto.EngineContext{Context: ctx}, pkStr, false)
				if err != nil {
					return crypto.FormatMCPError(err, "verify_file")
				}
				pubKeys = append(pubKeys, pk)
			}

			var valid bool
			if threshold > 1 || len(pubKeys) > 1 {
				valid, err = engine.VerifyThreshold(&crypto.EngineContext{Context: ctx}, data, sig, pubKeys, int(threshold))
			} else {
				if len(pubKeys) == 0 {
					return mcp.NewToolResultError("public key required"), nil
				}
				valid, err = engine.Verify(&crypto.EngineContext{Context: ctx}, data, sig, pubKeys[0])
			}

			if err != nil {
				return crypto.FormatMCPError(err, "verify_file")
			}

			res := crypto.VerifyResult{
				Status:   "success",
				Verified: valid,
			}
			if !valid {
				res.Status = "failed"
			}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("fragment_file", mcp.WithDescription("Split a file into redundant erasure-coded fragments")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			input := getString(args, "input", "")
			output := getString(args, "output", input+"_fragments")
			dataShards, _ := args["data_shards"].(float64)
			parityShards, _ := args["parity_shards"].(float64)
			sigKeyPath := getString(args, "sign_with", "")

			if dataShards == 0 {
				dataShards = 5
			}
			if parityShards == 0 {
				parityShards = 3
			}

			fi, err := os.Stat(input)
			if err != nil {
				return crypto.FormatMCPError(err, "fragment_file")
			}

			in, err := os.Open(input)
			if err != nil {
				return crypto.FormatMCPError(err, "fragment_file")
			}
			defer in.Close()

			var sigKey []byte
			if sigKeyPath != "" {
				passRaw := viper.GetString("passphrase")
				resolved := engine.ResolveKeyPath(&crypto.EngineContext{Context: ctx}, sigKeyPath, "")
				sigKey, err = engine.LoadPrivateKey(&crypto.EngineContext{Context: ctx}, resolved, []byte(passRaw), "", true)
				if err != nil {
					return crypto.FormatMCPError(err, "fragment_file")
				}
				defer crypto.SafeClear(sigKey)
			}

			opts := crypto.FragmentOptions{
				DataShards:   int(dataShards),
				ParityShards: int(parityShards),
				TargetDir:    output,
				OriginalSize: fi.Size(),
				SigningKey:   sigKey,
			}

			fw, err := crypto.NewFragmentWriter(opts)
			if err != nil {
				return crypto.FormatMCPError(err, "fragment_file")
			}
			defer fw.Close()

			if _, err := io.Copy(fw, in); err != nil {
				return crypto.FormatMCPError(err, "fragment_file")
			}

			res := map[string]any{
				"status":    "success",
				"shards":    int(dataShards + parityShards),
				"directory": output,
			}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("reassemble_file", mcp.WithDescription("Reconstruct a file from fragments")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			input := getString(args, "input_dir", "")
			output := getString(args, "output", "restored.data")
			authKeyPath := getString(args, "authorized_key", "")

			var authKey []byte
			if authKeyPath != "" {
				var err error
				authKey, err = os.ReadFile(authKeyPath)
				if err != nil {
					return crypto.FormatMCPError(err, "reassemble_file")
				}
			}

			f, err := os.Create(output)
			if err != nil {
				return crypto.FormatMCPError(err, "reassemble_file")
			}
			defer f.Close()

			if err := crypto.ReassembleFragments(input, f, authKey); err != nil {
				return crypto.FormatMCPError(err, "reassemble_file")
			}

			res := map[string]any{
				"status": "success",
				"file":   output,
			}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("inspect_file",
		mcp.WithDescription("Analyze header metadata"),
	),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			in, _ := os.Open(getString(args, "path", ""))
			if in == nil {
				return mcp.NewToolResultError("failed to open file"), nil
			}
			defer in.Close()

			stealth, _ := args["stealth"].(bool)
			info, err := engine.Inspect(nil, in, stealth)
			if err != nil {
				return crypto.FormatMCPError(err, "inspect_file")
			}
			res, _ := json.Marshal(info)
			return mcp.NewToolResultText(string(res)), nil
		})

	s.AddTool(mcp.NewTool("gen_passphrase",
		mcp.WithDescription("Generate a secure mnemonic"),
	),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			words, _ := args["words"].(float64)
			if words == 0 {
				words = 4
			}
			pass, err := engine.GeneratePassphrase(nil, int(words), "-")
			if err != nil {
				return crypto.FormatMCPError(err, "gen_passphrase")
			}
			res := crypto.GenResult{Passphrase: pass}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("gen_password",
		mcp.WithDescription("Generate a high-entropy secure password"),
	),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			length, _ := args["length"].(float64)
			if length == 0 {
				length = 32
			}
			noSymbols, _ := args["no_symbols"].(bool)
			pass, err := engine.GeneratePassword(nil, int(length), noSymbols)
			if err != nil {
				return crypto.FormatMCPError(err, "gen_password")
			}
			res := crypto.GenResult{Password: pass}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})
}
