package main

import (
	"bufio"
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

	// Tool: send_file
	sendFile := mcp.NewTool("send_file",
		mcp.WithDescription("Send a file, directory, or raw text via secure ephemeral P2P and return a code"),
	)
	sendFile.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"path":           map[string]interface{}{"type": "string", "description": "Path to the file or directory to send"},
			"text":           map[string]interface{}{"type": "string", "description": "Raw text to send instead of a file"},
			"public_key":     map[string]interface{}{"type": "string", "description": "Encrypt for a specific recipient's identity"},
			"stealth":        map[string]interface{}{"type": "boolean", "description": "Enable stealth mode"},
			"rendezvous_url": map[string]interface{}{"type": "string", "description": "Custom rendezvous server URL"},
			"transit_relay":  map[string]interface{}{"type": "string", "description": "Custom transit relay address"},
		},
	}
	s.AddTool(sendFile, sendHandler)

	// Tool: receive_file
	receiveFile := mcp.NewTool("receive_file",
		mcp.WithDescription("Receive a file, directory, or text via secure ephemeral P2P using a code"),
	)
	receiveFile.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"code":           map[string]interface{}{"type": "string", "description": "The receiver code from the sender"},
			"passphrase":     map[string]interface{}{"type": "string", "description": "The session passphrase from the sender (for symmetric mode)"},
			"private_key":    map[string]interface{}{"type": "string", "description": "Path to your private key (for identity-based mode)"},
			"output":         map[string]interface{}{"type": "string", "description": "Output path or directory (use '-' for stdout)"},
			"stealth":        map[string]interface{}{"type": "boolean", "description": "Enable stealth mode detection"},
			"rendezvous_url": map[string]interface{}{"type": "string", "description": "Custom rendezvous server URL"},
			"transit_relay":  map[string]interface{}{"type": "string", "description": "Custom transit relay address"},
		},
		Required: []string{"code"},
	}
	s.AddTool(receiveFile, receiveHandler)

	// Tool: start_chat
	startChat := mcp.NewTool("start_chat",
		mcp.WithDescription("Start a secure Ghost Chat session and return the join code"),
	)
	startChat.InputSchema = mcp.ToolInputSchema{
		Type:       "object",
		Properties: map[string]interface{}{},
	}
	s.AddTool(startChat, startChatHandler)

	// Tool: identity_active
	identityActive := mcp.NewTool("identity_active",
		mcp.WithDescription("List available Post-Quantum public keys on this system"),
	)
	identityActive.InputSchema = mcp.ToolInputSchema{
		Type:       "object",
		Properties: map[string]interface{}{},
	}
	s.AddTool(identityActive, identityActiveHandler)

	// Tool: identity_split
	identitySplit := mcp.NewTool("identity_split",
		mcp.WithDescription("Shard a private identity into mnemonic parts (Agent Mode)"),
	)
	identitySplit.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"name":       map[string]interface{}{"type": "string", "description": "Identity name"},
			"threshold":  map[string]interface{}{"type": "integer", "description": "Minimum shares required (default: 2)"},
			"shares":     map[string]interface{}{"type": "integer", "description": "Total shares (default: 3)"},
			"passphrase": map[string]interface{}{"type": "string", "description": "Unlock passphrase"},
		},
		Required: []string{"name"},
	}
	s.AddTool(identitySplit, identitySplitHandler)

	// Tool: vault_split
	vaultSplit := mcp.NewTool("vault_split",
		mcp.WithDescription("Shard the vault's master access key (Agent Mode)"),
	)
	vaultSplit.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"vault":      map[string]interface{}{"type": "string", "description": "Vault name (default: 'default')"},
			"threshold":  map[string]interface{}{"type": "integer", "description": "Minimum shares required"},
			"shares":     map[string]interface{}{"type": "integer", "description": "Total shares"},
			"passphrase": map[string]interface{}{"type": "string", "description": "Vault master passphrase"},
		},
	}
	s.AddTool(vaultSplit, vaultSplitHandler)

	// Tool: vault_recover
	vaultRecover := mcp.NewTool("vault_recover",
		mcp.WithDescription("Recover vault contents using shards (Agent Mode)"),
	)
	vaultRecover.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"shards":     map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "List of mnemonic shards"},
			"vault":      map[string]interface{}{"type": "string", "description": "Vault name (default: 'default')"},
			"output":     map[string]interface{}{"type": "string", "description": "Optional path to save recovered entries as a new vault"},
			"passphrase": map[string]interface{}{"type": "string", "description": "Passphrase for the new vault (if output is set)"},
		},
		Required: []string{"shards"},
	}
	s.AddTool(vaultRecover, vaultRecoverHandler)

	// Tool: identity_combine
	identityCombine := mcp.NewTool("identity_combine",
		mcp.WithDescription("Reconstruct a private identity from shards (Agent Mode)"),
	)
	identityCombine.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"shards":      map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "List of mnemonic shards"},
			"output":      map[string]interface{}{"type": "string", "description": "Name for the restored identity (default: 'restored_id')"},
			"passphrase":  map[string]interface{}{"type": "string", "description": "Passphrase to protect the restored identity"},
			"no_password": map[string]interface{}{"type": "boolean", "description": "Save unprotected"},
		},
		Required: []string{"shards"},
	}
	s.AddTool(identityCombine, identityCombineHandler)

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

func sendHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path := request.GetString("path", "")
	text := request.GetString("text", "")
	publicKey := request.GetString("public_key", "")
	stealth := request.GetBool("stealth", false)
	rendURL := request.GetString("rendezvous_url", "")
	transit := request.GetString("transit_relay", "")

	args := []string{"send", "--json"}
	if text != "" {
		args = append(args, "--text", text)
	} else if path != "" {
		args = append(args, path)
	} else {
		return mcp.NewToolResultError("Either 'path' or 'text' must be provided"), nil
	}

	if publicKey != "" {
		args = append(args, "--public-key", publicKey)
	}
	if stealth {
		args = append(args, "--stealth")
	}
	if rendURL != "" {
		args = append(args, "--rendezvous-url", rendURL)
	}
	if transit != "" {
		args = append(args, "--transit-relay", transit)
	}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Send failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func receiveHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	code := request.GetString("code", "")
	passphrase := request.GetString("passphrase", "")
	privateKey := request.GetString("private_key", "")
	output := request.GetString("output", "")
	stealth := request.GetBool("stealth", false)
	rendURL := request.GetString("rendezvous_url", "")
	transit := request.GetString("transit_relay", "")

	args := []string{"receive", code, "--json"}
	if passphrase != "" {
		args = append(args, "--passphrase", passphrase)
	}
	if privateKey != "" {
		args = append(args, "--private-key", privateKey)
	}
	if output != "" {
		args = append(args, "--output", output)
	}
	if stealth {
		args = append(args, "--stealth")
	}
	if rendURL != "" {
		args = append(args, "--rendezvous-url", rendURL)
	}
	if transit != "" {
		args = append(args, "--transit-relay", transit)
	}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Receive failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func startChatHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// We run 'chat --json' to get the code, then we can kill it.
	// The agent will then use the code to join or the user will use it.
	cmd := exec.CommandContext(ctx, getMaknoonBinary(), "chat", "--json")
	cmd.Env = getMaknoonEnv()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to open pipe: %v", err)), nil
	}

	if err := cmd.Start(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to start chat: %v", err)), nil
	}

	// Read the first JSON line (the established status with code)
	scanner := bufio.NewScanner(stdout)
	if scanner.Scan() {
		line := scanner.Text()
		// We have the code! Now we kill the process because this tool is just for starting.
		_ = cmd.Process.Kill()
		return mcp.NewToolResultText(line), nil
	}

	return mcp.NewToolResultError("Failed to get chat code"), nil
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

func identitySplitHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := request.GetString("name", "")
	threshold := request.GetInt("threshold", 0)
	shares := request.GetInt("shares", 0)
	passphrase := request.GetString("passphrase", "")

	args := []string{"identity", "split", name, "--json"}
	if threshold > 0 {
		args = append(args, "--threshold", fmt.Sprintf("%d", threshold))
	}
	if shares > 0 {
		args = append(args, "--shares", fmt.Sprintf("%d", shares))
	}
	if passphrase != "" {
		args = append(args, "--passphrase", passphrase)
	}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Identity split failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func vaultSplitHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	vault := request.GetString("vault", "default")
	threshold := request.GetInt("threshold", 0)
	shares := request.GetInt("shares", 0)
	passphrase := request.GetString("passphrase", "")

	args := []string{"vault", "split", "--vault", vault, "--json"}
	if threshold > 0 {
		args = append(args, "--threshold", fmt.Sprintf("%d", threshold))
	}
	if shares > 0 {
		args = append(args, "--shares", fmt.Sprintf("%d", shares))
	}
	if passphrase != "" {
		args = append(args, "--passphrase", passphrase)
	}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Vault split failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func vaultRecoverHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	shards := request.Get("shards").([]interface{})
	vault := request.GetString("vault", "default")
	output := request.GetString("output", "")
	passphrase := request.GetString("passphrase", "")

	args := []string{"vault", "recover"}
	for _, s := range shards {
		args = append(args, s.(string))
	}
	args = append(args, "--vault", vault, "--json")
	if output != "" {
		args = append(args, "--output", output)
	}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = getMaknoonEnv()
	if passphrase != "" {
		cmd.Env = append(cmd.Env, "MAKNOON_PASSPHRASE="+passphrase)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Vault recover failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func identityCombineHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	shards := request.Get("shards").([]interface{})
	output := request.GetString("output", "restored_id")
	passphrase := request.GetString("passphrase", "")
	noPassword := request.GetBool("no_password", false)

	args := []string{"identity", "combine"}
	for _, s := range shards {
		args = append(args, s.(string))
	}
	args = append(args, "--output", output, "--json")
	if noPassword {
		args = append(args, "--no-password")
	}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = getMaknoonEnv()
	if passphrase != "" {
		cmd.Env = append(cmd.Env, "MAKNOON_PASSPHRASE="+passphrase)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Identity combine failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}
