package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := createServer()
	if err := server.ServeStdio(s); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

func createServer() *server.MCPServer {
	s := server.NewMCPServer(
		"Maknoon PQC Server",
		"1.3.2",
		server.WithLogging(),
	)

	// Tool: vault_get
	vaultGet := mcp.NewTool("vault_get",
		mcp.WithDescription("Retrieve a secret from the Maknoon vault"),
	)
	vaultGet.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"service": map[string]interface{}{"type": "string", "description": "Name of the service (e.g., github.com)"},
			"vault":   map[string]interface{}{"type": "string", "description": "Vault name (default: 'default')"},
		},
		Required: []string{"service"},
	}
	s.AddTool(vaultGet, vaultGetHandler)

	// Tool: vault_set
	vaultSet := mcp.NewTool("vault_set",
		mcp.WithDescription("Store a secret in the Maknoon vault"),
	)
	vaultSet.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"service":  map[string]interface{}{"type": "string", "description": "Name of the service"},
			"password": map[string]interface{}{"type": "string", "description": "The secret password to store"},
			"username": map[string]interface{}{"type": "string"},
			"vault":    map[string]interface{}{"type": "string"},
		},
		Required: []string{"service", "password"},
	}
	s.AddTool(vaultSet, vaultSetHandler)

	// Tool: encrypt_file
	encryptFile := mcp.NewTool("encrypt_file",
		mcp.WithDescription("Encrypt a file using Maknoon Post-Quantum cryptography"),
	)
	encryptFile.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"input":      map[string]interface{}{"type": "string", "description": "Path to the file to encrypt"},
			"output":     map[string]interface{}{"type": "string", "description": "Path for the encrypted output"},
			"public_key": map[string]interface{}{"type": "string", "description": "Optional path to the recipient's public key"},
		},
		Required: []string{"input", "output"},
	}
	s.AddTool(encryptFile, encryptHandler)

	// Tool: decrypt_file
	decryptFile := mcp.NewTool("decrypt_file",
		mcp.WithDescription("Decrypt a .makn file using a private key"),
	)
	decryptFile.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"input":       map[string]interface{}{"type": "string", "description": "Path to the .makn file"},
			"output":      map[string]interface{}{"type": "string", "description": "Path for the decrypted output (use '-' for stdout)"},
			"private_key": map[string]interface{}{"type": "string", "description": "Path to your private key"},
		},
		Required: []string{"input", "output"},
	}
	s.AddTool(decryptFile, decryptHandler)

	// Tool: gen_password
	genPassword := mcp.NewTool("gen_password",
		mcp.WithDescription("Generate a high-entropy secure password"),
	)
	genPassword.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"length":     map[string]interface{}{"type": "integer", "description": "Length of the password (default: 32)"},
			"no_symbols": map[string]interface{}{"type": "boolean", "description": "Exclude symbols"},
		},
	}
	s.AddTool(genPassword, genPasswordHandler)

	// Tool: gen_passphrase
	genPassphrase := mcp.NewTool("gen_passphrase",
		mcp.WithDescription("Generate a mnemonic secure passphrase"),
	)
	genPassphrase.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"words":     map[string]interface{}{"type": "integer", "description": "Number of words (default: 4)"},
			"separator": map[string]interface{}{"type": "string", "description": "Separator (default: '-')"},
		},
	}
	s.AddTool(genPassphrase, genPassphraseHandler)

	// Tool: inspect_file
	inspectFile := mcp.NewTool("inspect_file",
		mcp.WithDescription("Inspect a Maknoon encrypted file's metadata"),
	)
	inspectFile.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"path":    map[string]interface{}{"type": "string", "description": "Path to the encrypted file"},
			"stealth": map[string]interface{}{"type": "boolean", "description": "Enable stealth mode detection"},
		},
		Required: []string{"path"},
	}
	s.AddTool(inspectFile, inspectHandler)

	// Tool: identity_active
	identityActive := mcp.NewTool("identity_active",
		mcp.WithDescription("List available Post-Quantum public keys on this system"),
	)
	identityActive.InputSchema = mcp.ToolInputSchema{
		Type:       "object",
		Properties: map[string]interface{}{},
	}
	s.AddTool(identityActive, identityActiveHandler)

	return s
}

func getMaknoonBinary() string {
	if b := os.Getenv("MAKNOON_BINARY"); b != "" {
		return b
	}
	return "maknoon"
}

func getMaknoonEnv() []string {
	env := []string{"MAKNOON_JSON=1"}
	vars := []string{"MAKNOON_PASSPHRASE", "MAKNOON_PUBLIC_KEY", "MAKNOON_PRIVATE_KEY", "HOME", "PATH"}
	for _, v := range vars {
		if val := os.Getenv(v); val != "" {
			env = append(env, v+"="+val)
		}
	}
	return env
}

func vaultGetHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	service := request.GetString("service", "")
	vault := request.GetString("vault", "default")

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), "vault", "get", service, "--vault", vault, "--json")
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Vault get failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func vaultSetHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	service := request.GetString("service", "")
	password := request.GetString("password", "")
	username := request.GetString("username", "")
	vault := request.GetString("vault", "default")

	args := []string{"vault", "set", service, "--json", "--vault", vault}
	if username != "" {
		args = append(args, "--user", username)
	}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = append(getMaknoonEnv(), "MAKNOON_PASSWORD="+password)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Vault set failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func encryptHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := request.GetString("input", "")
	output := request.GetString("output", "")
	publicKey := request.GetString("public_key", "")

	args := []string{"encrypt", input, "-o", output, "--json", "--quiet"}
	if publicKey != "" {
		args = append(args, "-p", publicKey)
	}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Encryption failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func decryptHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := request.GetString("input", "")
	output := request.GetString("output", "")
	privateKey := request.GetString("private_key", "")

	args := []string{"decrypt", input, "-o", output, "--json", "--quiet"}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = getMaknoonEnv()
	if privateKey != "" {
		cmd.Env = append(cmd.Env, "MAKNOON_PRIVATE_KEY="+privateKey)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Decryption failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func genPasswordHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	length := request.GetInt("length", 32)
	noSymbols := request.GetBool("no_symbols", false)

	args := []string{"gen", "password", "--length", fmt.Sprintf("%d", length), "--json"}
	if noSymbols {
		args = append(args, "--no-symbols")
	}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Password generation failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func genPassphraseHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	words := request.GetInt("words", 4)
	separator := request.GetString("separator", "-")

	args := []string{"gen", "passphrase", "--words", fmt.Sprintf("%d", words), "--separator", separator, "--json"}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Passphrase generation failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func inspectHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path := request.GetString("path", "")
	stealth := request.GetBool("stealth", false)

	args := []string{"info", path, "--json"}
	if stealth {
		args = append(args, "--stealth")
	}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("File inspection failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func identityActiveHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cmd := exec.CommandContext(ctx, getMaknoonBinary(), "identity", "active", "--json")
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Identity active failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}
