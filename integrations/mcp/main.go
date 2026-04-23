package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var engine crypto.MaknoonEngine

func main() {
	if err := initEngine(); err != nil {
		fmt.Printf("Engine initialization failed: %v\n", err)
		os.Exit(1)
	}
	s := createServer()
	if err := server.ServeStdio(s); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

func initEngine() error {
	policy := &crypto.AgentPolicy{}
	core, err := crypto.NewEngine(policy)
	if err != nil {
		return err
	}

	// MCP server always uses NoopLogger (Stealth) for now to avoid polluting logs
	// unless specifically requested by user in future.
	engine = &crypto.AuditEngine{
		Engine: core,
		Logger: &crypto.NoopLogger{},
	}
	return nil
}

func formatError(err error, toolName string) (*mcp.CallToolResult, error) {
	resp := map[string]interface{}{
		"error": err.Error(),
		"tool":  toolName,
	}

	var policyErr *crypto.ErrPolicyViolation
	var authErr *crypto.ErrAuthentication
	var cryptoErr *crypto.ErrCrypto
	var stateErr *crypto.ErrState

	if crypto.As(err, &policyErr) {
		resp["type"] = "security_policy_violation"
		resp["is_security_violation"] = true
		resp["code"] = 403
	} else if crypto.As(err, &authErr) {
		resp["type"] = "authentication_failed"
		resp["code"] = 401
	} else if crypto.As(err, &cryptoErr) {
		resp["type"] = "cryptographic_failure"
		resp["code"] = 500
	} else if crypto.As(err, &stateErr) {
		resp["type"] = "system_state_error"
		resp["code"] = 503
	}

	raw, _ := json.Marshal(resp)
	return mcp.NewToolResultError(string(raw)), nil
}

func createServer() *server.MCPServer {
	// Ensure engine is initialized
	if engine == nil {
		if err := initEngine(); err != nil {
			// In a real server this might be handled better, but for MCP
			// we must have an engine to proceed.
			panic(fmt.Sprintf("failed to initialize engine: %v", err))
		}
	}

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
			"input":              map[string]interface{}{"type": "string", "description": "Path to the .makn file"},
			"output":             map[string]interface{}{"type": "string", "description": "Path for the decrypted output (use '-' for stdout)"},
			"private_key":        map[string]interface{}{"type": "string", "description": "Path to your private key"},
			"trust_on_first_use": map[string]interface{}{"type": "boolean", "description": "Automatically add unknown signers to contacts"},
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

	// Tool: identity_publish
	identityPublish := mcp.NewTool("identity_publish",
		mcp.WithDescription("Anchor your active identity globally (Nostr/DNS) or locally"),
	)
	identityPublish.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"handle":      map[string]interface{}{"type": "string", "description": "Global handle (e.g., @alice or @domain.com)"},
			"name":        map[string]interface{}{"type": "string", "description": "Name of the local identity to publish"},
			"nostr":       map[string]interface{}{"type": "boolean", "description": "Publish to Nostr relays (Default)"},
			"dns":         map[string]interface{}{"type": "boolean", "description": "Generate DNS TXT record"},
			"local":       map[string]interface{}{"type": "boolean", "description": "Publish to local registry only"},
			"desec":       map[string]interface{}{"type": "boolean", "description": "Automatically publish to deSEC.io"},
			"desec_token": map[string]interface{}{"type": "string", "description": "deSEC.io API token"},
		},
		Required: []string{"handle"},
	}
	s.AddTool(identityPublish, identityPublishHandler)

	// Tool: contact_add
	contactAdd := mcp.NewTool("contact_add",
		mcp.WithDescription("Add a new trusted contact (Petname)"),
	)
	contactAdd.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"petname": map[string]interface{}{"type": "string", "description": "Local alias (e.g., @boss)"},
			"kem_pub": map[string]interface{}{"type": "string", "description": "Path to the contact's ML-KEM public key file"},
			"sig_pub": map[string]interface{}{"type": "string", "description": "Optional path to the contact's ML-DSA public key file"},
			"note":    map[string]interface{}{"type": "string", "description": "Optional note"},
		},
		Required: []string{"petname", "kem_pub"},
	}
	s.AddTool(contactAdd, contactAddHandler)

	// Tool: contact_list
	contactList := mcp.NewTool("contact_list",
		mcp.WithDescription("List all trusted contacts in your address book"),
	)
	contactList.InputSchema = mcp.ToolInputSchema{
		Type:       "object",
		Properties: map[string]interface{}{},
	}
	s.AddTool(contactList, contactListHandler)

	// Tool: profiles_list
	profilesList := mcp.NewTool("profiles_list",
		mcp.WithDescription("List all available cryptographic profiles"),
	)
	profilesList.InputSchema = mcp.ToolInputSchema{
		Type:       "object",
		Properties: map[string]interface{}{},
	}
	s.AddTool(profilesList, profilesListHandler)

	// Tool: profiles_gen
	profilesGen := mcp.NewTool("profiles_gen",
		mcp.WithDescription("Generate a new random, validated profile and save it to config"),
	)
	profilesGen.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"name": map[string]interface{}{"type": "string", "description": "Name for the new profile"},
		},
		Required: []string{"name"},
	}
	s.AddTool(profilesGen, profilesGenHandler)

	return s
}

func getMaknoonBinary() string {
	if b := os.Getenv("MAKNOON_BINARY"); b != "" {
		return b
	}
	return "maknoon"
}

func getMaknoonEnv() []string {
	env := []string{"MAKNOON_JSON=1", "MAKNOON_AGENT_MODE=1"}
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
	_ = request.GetString("vault", "default")

	// Get master passphrase from environment (Agent convention)
	passphrase := []byte(os.Getenv("MAKNOON_PASSPHRASE"))

	entry, err := engine.VaultGet("", service, passphrase, "")
	if err != nil {
		return formatError(err, "vault_get")
	}

	if entry == nil {
		return mcp.NewToolResultError(`{"error":"service not found","code":404}`), nil
	}

	raw, _ := json.Marshal(entry)
	return mcp.NewToolResultText(string(raw)), nil
}

func vaultSetHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	service := request.GetString("service", "")
	password := request.GetString("password", "")
	username := request.GetString("username", "")
	_ = request.GetString("vault", "default")

	// Get master passphrase from environment
	passphrase := []byte(os.Getenv("MAKNOON_PASSPHRASE"))

	entry := &crypto.VaultEntry{
		Service:  service,
		Username: username,
		Password: []byte(password),
	}

	err := engine.VaultSet("", entry, passphrase, "")
	if err != nil {
		return formatError(err, "vault_set")
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"status":"success","service":"%s"}`, service)), nil
}

func encryptHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := request.GetString("input", "")
	output := request.GetString("output", "")
	pubKey := request.GetString("public_key", "")

	args := []string{"encrypt", input, "-o", output, "--json"}
	if pubKey != "" {
		args = append(args, "-p", pubKey)
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
	privKey := request.GetString("private_key", "")
	tofu := request.GetBool("trust_on_first_use", false)

	args := []string{"decrypt", input, "-o", output, "--json"}
	if privKey != "" {
		args = append(args, "-k", privKey)
	}
	if tofu {
		args = append(args, "--trust-on-first-use")
	}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = getMaknoonEnv()

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
	shards := request.GetStringSlice("shards", nil)
	vault := request.GetString("vault", "default")
	output := request.GetString("output", "")
	passphrase := request.GetString("passphrase", "")

	args := []string{"vault", "recover"}
	args = append(args, shards...)
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
	shards := request.GetStringSlice("shards", nil)
	output := request.GetString("output", "restored_id")
	passphrase := request.GetString("passphrase", "")
	noPassword := request.GetBool("no_password", false)

	args := []string{"identity", "combine"}
	args = append(args, shards...)
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

func identityPublishHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	handle := request.GetString("handle", "")
	name := request.GetString("name", "")
	nostr := request.GetBool("nostr", false)
	dns := request.GetBool("dns", false)
	local := request.GetBool("local", false)
	desec := request.GetBool("desec", false)
	desecToken := request.GetString("desec_token", "")

	args := []string{"identity", "publish", handle, "--json"}
	if name != "" {
		args = append(args, "--name", name)
	}
	if nostr {
		args = append(args, "--nostr")
	}
	if dns {
		args = append(args, "--dns")
	}
	if local {
		args = append(args, "--local")
	}
	if desec {
		args = append(args, "--desec")
	}
	if desecToken != "" {
		args = append(args, "--desec-token", desecToken)
	}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Identity publish failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func contactAddHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	petname := request.GetString("petname", "")
	kemPub := request.GetString("kem_pub", "")
	sigPub := request.GetString("sig_pub", "")
	note := request.GetString("note", "")

	args := []string{"contact", "add", petname, "--kem-pub", kemPub, "--json"}
	if sigPub != "" {
		args = append(args, "--sig-pub", sigPub)
	}
	if note != "" {
		args = append(args, "--note", note)
	}

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), args...)
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Contact add failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func contactListHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cmd := exec.CommandContext(ctx, getMaknoonBinary(), "contact", "list", "--json")
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Contact list failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func profilesListHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cmd := exec.CommandContext(ctx, getMaknoonBinary(), "profiles", "list", "--json")
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Profiles list failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func profilesGenHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := request.GetString("name", "")
	cmd := exec.CommandContext(ctx, getMaknoonBinary(), "profiles", "gen", name, "--json")
	cmd.Env = getMaknoonEnv()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Profiles generation failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}
