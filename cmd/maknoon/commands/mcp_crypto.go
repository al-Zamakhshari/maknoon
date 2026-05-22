package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"
)

func registerCryptoTools(s *server.MCPServer, engine crypto.MaknoonEngine) {
	s.AddTool(mcp.NewTool("encrypt_file",
		mcp.WithDescription("Encrypt a file or directory using PQC hybrid encryption. Set recursive=true to encrypt each file in a directory individually — the passphrase KDF runs once for the whole run, not once per file. Set threshold≥2 with public_keys for K-of-N threshold encryption requiring threshold recipients to cooperate to decrypt."),
		mcp.WithString("input", mcp.Required(), mcp.Description("Path to file or directory to encrypt")),
		mcp.WithString("output", mcp.Required(), mcp.Description("Output path for the .makn file, or output directory when recursive=true")),
		mcp.WithString("public_keys", mcp.Description("Comma-separated list of recipient key paths, petnames, or @handles (multi-recipient)")),
		mcp.WithNumber("profile", mcp.Description("Cryptographic profile ID: 1=NIST (ML-KEM+ML-DSA), 3=Conservative (FrodoKEM+SLH-DSA)")),
		mcp.WithBoolean("recursive", mcp.Description("Encrypt each file in a directory individually (one KDF call total). Produces a .makn file per input file.")),
		mcp.WithNumber("threshold", mcp.Description("K for K-of-N threshold encryption (≥2). Requires public_keys to be set with N recipient keys. Any K key holders can decrypt; fewer cannot.")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		input := getString(args, "input", "")
		output := getString(args, "output", "")
		recursive := getBool(args, "recursive", false)
		thresholdK := getInt(args, "threshold", 0)

		opts := crypto.Options{}
		if passRaw := viper.GetString("passphrase"); passRaw != "" {
			opts.Passphrase = crypto.SecretBytes(passRaw)
		}

		// Multi-recipient: comma-separated key paths / petnames / @handles
		if pkList := getString(args, "public_keys", ""); pkList != "" {
			for _, pk := range strings.Split(pkList, ",") {
				pk = strings.TrimSpace(pk)
				if pk == "" {
					continue
				}
				data, err := engine.ResolvePublicKey(&crypto.EngineContext{Context: ctx}, pk, false)
				if err != nil {
					return crypto.FormatMCPError(fmt.Errorf("cannot resolve key %q: %w", pk, err), "encrypt_file")
				}
				opts.Recipients = append(opts.Recipients, data)
			}
		}

		if pid := getInt(args, "profile", 0); pid != 0 {
			b := byte(pid)
			opts.ProfileID = &b
		}

		// Threshold encryption: K-of-N, requires public_keys and threshold≥2.
		if thresholdK >= 2 && len(opts.Recipients) >= thresholdK {
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
			if err := engine.EncryptThreshold(&crypto.EngineContext{Context: ctx}, in, out, opts.Recipients, thresholdK, opts); err != nil {
				return crypto.FormatMCPError(err, "encrypt_file")
			}
			res := map[string]any{
				"status":    "success",
				"output":    output,
				"threshold": thresholdK,
				"total":     len(opts.Recipients),
			}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		}

		fi, err := os.Stat(input)
		if err != nil {
			return crypto.FormatMCPError(err, "encrypt_file")
		}

		// Recursive directory encryption — one session key for all files.
		if recursive && fi.IsDir() {
			res, err := engine.ProtectDirectory(&crypto.EngineContext{Context: ctx}, input, output, opts)
			if err != nil {
				return crypto.FormatMCPError(err, "encrypt_file")
			}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		}

		opts.IsArchive = fi.IsDir()

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

		res, err := engine.Protect(&crypto.EngineContext{Context: ctx}, fi.Name(), in, out, opts)
		if err != nil {
			return crypto.FormatMCPError(err, "encrypt_file")
		}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("decrypt_file",
		mcp.WithDescription("Decrypt a .makn file"),
		mcp.WithString("input", mcp.Required(), mcp.Description("Path to the .makn encrypted file")),
		mcp.WithString("output", mcp.Required(), mcp.Description("Output path for the decrypted file or directory")),
		mcp.WithString("private_key", mcp.Description("Path to private key file (uses server passphrase if omitted)")),
		mcp.WithString("sender_key", mcp.Description("Path to sender's public key for signature verification")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		input := getString(args, "input", "")
		output := getString(args, "output", "")
		keyPath := getString(args, "private_key", "")
		senderKeyPath := getString(args, "sender_key", "")

		opts := crypto.Options{}
		passRaw := viper.GetString("passphrase")

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

	s.AddTool(mcp.NewTool("sign_file",
		mcp.WithDescription("Sign a file using an ML-DSA private key"),
		mcp.WithString("path", mcp.Required(), mcp.Description("Path to the file to sign")),
		mcp.WithString("private_key", mcp.Required(), mcp.Description("Path to the ML-DSA private key")),
		mcp.WithString("output", mcp.Description("Output path for the signature (default: <path>.sig)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	s.AddTool(mcp.NewTool("verify_file",
		mcp.WithDescription("Verify a file's ML-DSA signature (supports M-of-N threshold verification)"),
		mcp.WithString("path", mcp.Required(), mcp.Description("Path to the file to verify")),
		mcp.WithString("signature", mcp.Required(), mcp.Description("Path to the .sig signature file")),
		mcp.WithString("public_keys", mcp.Required(), mcp.Description("Comma-separated list of public key paths or petnames")),
		mcp.WithNumber("threshold", mcp.Description("Minimum number of valid signatures required (default: 1)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		path := getString(args, "path", "")
		sigPath := getString(args, "signature", "")
		pubKeyList := getString(args, "public_keys", "")
		threshold := getInt(args, "threshold", 1)

		data, err := os.ReadFile(path)
		if err != nil {
			return crypto.FormatMCPError(err, "verify_file")
		}
		sig, err := os.ReadFile(sigPath)
		if err != nil {
			return crypto.FormatMCPError(err, "verify_file")
		}

		var pubKeys [][]byte
		for _, p := range strings.Split(pubKeyList, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			pk, err := engine.ResolvePublicKey(&crypto.EngineContext{Context: ctx}, p, false)
			if err != nil {
				return crypto.FormatMCPError(err, "verify_file")
			}
			pubKeys = append(pubKeys, pk)
		}

		if len(pubKeys) == 0 {
			return mcp.NewToolResultError("at least one public key is required"), nil
		}

		var valid bool
		if threshold > 1 || len(pubKeys) > 1 {
			valid, err = engine.VerifyThreshold(&crypto.EngineContext{Context: ctx}, data, sig, pubKeys, threshold)
		} else {
			valid, err = engine.Verify(&crypto.EngineContext{Context: ctx}, data, sig, pubKeys[0])
		}
		if err != nil {
			return crypto.FormatMCPError(err, "verify_file")
		}

		res := crypto.VerifyResult{Status: "success", Verified: valid}
		if !valid {
			res.Status = "failed"
		}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("inspect_file",
		mcp.WithDescription("Read a .makn file's header metadata without decrypting"),
		mcp.WithString("path", mcp.Required(), mcp.Description("Path to the .makn file")),
		mcp.WithBoolean("stealth", mcp.Description("Enable fingerprint-resistant inspection mode")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		in, err := os.Open(getString(args, "path", ""))
		if err != nil {
			return crypto.FormatMCPError(err, "inspect_file")
		}
		defer in.Close()

		stealth := getBool(args, "stealth", false)
		info, err := engine.Inspect(&crypto.EngineContext{Context: ctx}, in, stealth)
		if err != nil {
			return crypto.FormatMCPError(err, "inspect_file")
		}
		res, _ := json.Marshal(info)
		return mcp.NewToolResultText(string(res)), nil
	})

	s.AddTool(mcp.NewTool("gen_passphrase",
		mcp.WithDescription("Generate a secure mnemonic passphrase from an entropy-backed word list"),
		mcp.WithNumber("words", mcp.Description("Number of words (default: 6)")),
		mcp.WithString("store_service", mcp.Description("If set, store result in vault under this service name")),
		mcp.WithString("store_vault", mcp.Description("Vault name for storage (default: 'default')")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		words := getInt(args, "words", 6)
		pass, err := engine.GeneratePassphrase(&crypto.EngineContext{Context: ctx}, words, "-")
		if err != nil {
			return crypto.FormatMCPError(err, "gen_passphrase")
		}
		bits := crypto.PassphraseEntropy(words, len(crypto.PassphraseWordList))
		res := crypto.GenResult{
			Passphrase:    pass,
			EntropyBits:   bits,
			EntropyBitsPQ: bits / 2,
		}
		if svc := getString(args, "store_service", ""); svc != "" {
			vaultName := getString(args, "store_vault", "default")
			vaultPath := viper.GetString("vault_path")
			if vaultPath == "" {
				vaultPath, _ = resolveVaultPath(vaultName)
			}
			vPass := []byte(viper.GetString("passphrase"))
			entry := &crypto.VaultEntry{Service: svc, Password: crypto.SecretBytes(pass)}
			if err := engine.VaultSet(&crypto.EngineContext{Context: ctx}, vaultPath, entry, vPass, "", false); err != nil {
				return crypto.FormatMCPError(err, "gen_passphrase")
			}
		}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("gen_password",
		mcp.WithDescription("Generate a high-entropy random password"),
		mcp.WithNumber("length", mcp.Description("Password length in characters (default: 32)")),
		mcp.WithBoolean("no_symbols", mcp.Description("Omit special characters (default: false)")),
		mcp.WithString("store_service", mcp.Description("If set, store result in vault under this service name")),
		mcp.WithString("store_vault", mcp.Description("Vault name for storage (default: 'default')")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		length := getInt(args, "length", 32)
		noSymbols := getBool(args, "no_symbols", false)
		pass, err := engine.GeneratePassword(&crypto.EngineContext{Context: ctx}, length, noSymbols)
		if err != nil {
			return crypto.FormatMCPError(err, "gen_password")
		}
		bits := crypto.PasswordEntropy(length, crypto.PasswordCharsetSize(noSymbols))
		res := crypto.GenResult{
			Password:      pass,
			EntropyBits:   bits,
			EntropyBitsPQ: bits / 2,
		}
		if svc := getString(args, "store_service", ""); svc != "" {
			vaultName := getString(args, "store_vault", "default")
			vaultPath := viper.GetString("vault_path")
			if vaultPath == "" {
				vaultPath, _ = resolveVaultPath(vaultName)
			}
			vPass := []byte(viper.GetString("passphrase"))
			entry := &crypto.VaultEntry{Service: svc, Password: crypto.SecretBytes(pass)}
			if err := engine.VaultSet(&crypto.EngineContext{Context: ctx}, vaultPath, entry, vPass, "", false); err != nil {
				return crypto.FormatMCPError(err, "gen_password")
			}
		}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("reencrypt_file",
		mcp.WithDescription("Re-encrypt a .makn file with a different cryptographic profile (passphrase read from server config)"),
		mcp.WithString("input", mcp.Required(), mcp.Description("Path to the encrypted .makn file")),
		mcp.WithString("output", mcp.Description("Output path (default: overwrite input)")),
		mcp.WithNumber("profile", mcp.Description("Target profile ID: 1=NIST, 3=Conservative/FrodoKEM")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		inputPath := getString(args, "input", "")
		outputPath := getString(args, "output", "")
		passphrase := []byte(viper.GetString("passphrase"))
		targetProfile := byte(getInt(args, "profile", 3))

		if inputPath == "" {
			return crypto.FormatMCPError(fmt.Errorf("input is required"), "reencrypt_file")
		}
		if outputPath == "" {
			outputPath = inputPath
		}

		f, err := os.Open(inputPath)
		if err != nil {
			return crypto.FormatMCPError(err, "reencrypt_file")
		}
		defer f.Close()

		result, err := reencryptReader(f, passphrase, targetProfile)
		if err != nil {
			return crypto.FormatMCPError(err, "reencrypt_file")
		}

		outFile, err := os.Create(outputPath)
		if err != nil {
			return crypto.FormatMCPError(err, "reencrypt_file")
		}
		defer outFile.Close()
		if _, err := io.Copy(outFile, result); err != nil {
			return crypto.FormatMCPError(err, "reencrypt_file")
		}

		res := map[string]any{"status": "success", "output": outputPath, "to_profile": targetProfile}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("session_derive",
		mcp.WithDescription("Derive a one-time session key from a passphrase. The returned session_key bypasses Argon2id on every subsequent encrypt/decrypt call (~683× faster for small files). Use this once at the start of a bulk operation, pass session_key and session_salt to encrypt_file, then discard both values when done."),
		mcp.WithString("passphrase", mcp.Required(), mcp.Description("Passphrase to derive the session key from")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		_ = ctx
		passphrase := getString(getArgs(request), "passphrase", "")
		if passphrase == "" {
			return mcp.NewToolResultError("passphrase is required"), nil
		}
		key, salt, err := crypto.DeriveSessionKey([]byte(passphrase))
		if err != nil {
			return crypto.FormatMCPError(err, "session_derive")
		}
		res := map[string]any{
			"session_key":  fmt.Sprintf("%x", key),
			"session_salt": fmt.Sprintf("%x", salt),
			"note":         "Pass session_key and session_salt to encrypt_file. Discard both after the bulk operation completes.",
		}
		crypto.SafeClear(key)
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("shred_file",
		mcp.WithDescription("Securely delete a file or directory (multi-pass overwrite + random rename + delete)"),
		mcp.WithString("path", mcp.Required(), mcp.Description("Path to the file or directory to shred")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		_ = ctx
		path := getString(getArgs(request), "path", "")
		if path == "" {
			return mcp.NewToolResultError("path is required"), nil
		}
		if err := engine.SecureDelete(path); err != nil {
			return crypto.FormatMCPError(err, "shred_file")
		}
		res := map[string]any{"status": "success", "shredded": path}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("threshold_collect_share",
		mcp.WithDescription("Collect this recipient's Shamir share from a threshold-encrypted .makn file. Run once per key holder. Gather K shares across recipients, then call threshold_combine_decrypt to decrypt."),
		mcp.WithString("input", mcp.Required(), mcp.Description("Path to the threshold-encrypted .makn file")),
		mcp.WithString("private_key", mcp.Required(), mcp.Description("Path to this recipient's private key file")),
		mcp.WithString("output", mcp.Description("Path to write the share JSON (default: <input>.share.json)")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		inputPath := getString(args, "input", "")
		keyPath := getString(args, "private_key", "")
		outputPath := getString(args, "output", inputPath+".share.json")

		passRaw := viper.GetString("passphrase")
		resolved := engine.ResolveKeyPath(&crypto.EngineContext{Context: ctx}, keyPath, "")
		priv, err := engine.LoadPrivateKey(&crypto.EngineContext{Context: ctx}, resolved, []byte(passRaw), "", true)
		if err != nil {
			return crypto.FormatMCPError(err, "threshold_collect_share")
		}
		defer crypto.SafeClear(priv)

		f, err := os.Open(inputPath)
		if err != nil {
			return crypto.FormatMCPError(err, "threshold_collect_share")
		}
		defer f.Close()

		share, err := engine.CollectThresholdShare(&crypto.EngineContext{Context: ctx}, f, priv, 0)
		if err != nil {
			return crypto.FormatMCPError(err, "threshold_collect_share")
		}

		shareJSON, err := crypto.ThresholdShareToJSON(share)
		if err != nil {
			return crypto.FormatMCPError(err, "threshold_collect_share")
		}
		if err := os.WriteFile(outputPath, shareJSON, 0600); err != nil {
			return crypto.FormatMCPError(err, "threshold_collect_share")
		}

		res := map[string]any{
			"share_file": outputPath,
			"index":      share.Index,
			"threshold":  share.Threshold,
			"total":      share.Total,
		}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})

	s.AddTool(mcp.NewTool("threshold_combine_decrypt",
		mcp.WithDescription("Combine K Shamir shares (collected via threshold_collect_share) and decrypt a threshold-encrypted .makn file. Provide at least K share files; the threshold K is read from the shares themselves."),
		mcp.WithString("input", mcp.Required(), mcp.Description("Path to the threshold-encrypted .makn file")),
		mcp.WithString("shares", mcp.Required(), mcp.Description("Comma-separated paths to the share JSON files (need at least K files)")),
		mcp.WithString("output", mcp.Required(), mcp.Description("Output path for the decrypted plaintext")),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := getArgs(request)
		inputPath := getString(args, "input", "")
		shareList := getString(args, "shares", "")
		outputPath := getString(args, "output", "")

		var shares []*crypto.ThresholdShare
		for _, sp := range strings.Split(shareList, ",") {
			sp = strings.TrimSpace(sp)
			if sp == "" {
				continue
			}
			data, err := os.ReadFile(sp)
			if err != nil {
				return crypto.FormatMCPError(fmt.Errorf("reading share file %q: %w", sp, err), "threshold_combine_decrypt")
			}
			share, err := crypto.ThresholdShareFromJSON(data)
			if err != nil {
				return crypto.FormatMCPError(fmt.Errorf("parsing share file %q: %w", sp, err), "threshold_combine_decrypt")
			}
			shares = append(shares, share)
		}
		if len(shares) == 0 {
			return mcp.NewToolResultError("no share files provided"), nil
		}

		src, err := os.Open(inputPath)
		if err != nil {
			return crypto.FormatMCPError(err, "threshold_combine_decrypt")
		}
		defer src.Close()

		if err := engine.CombineAndDecrypt(&crypto.EngineContext{Context: ctx}, src, nil, outputPath, shares); err != nil {
			return crypto.FormatMCPError(err, "threshold_combine_decrypt")
		}

		fi, _ := os.Stat(outputPath)
		var size int64
		if fi != nil {
			size = fi.Size()
		}
		res := map[string]any{
			"status":        "success",
			"output":        outputPath,
			"bytes_written": size,
			"shares_used":   len(shares),
		}
		outData, _ := json.Marshal(res)
		return mcp.NewToolResultText(string(outData)), nil
	})
}
