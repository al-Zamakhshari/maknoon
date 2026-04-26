package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"
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
	// Initialize Viper for the MCP server
	viper.SetEnvPrefix("MAKNOON")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

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

	// Tool: vault_list
	vaultList := mcp.NewTool("vault_list",
		mcp.WithDescription("List services in a vault"),
	)
	vaultList.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"vault": map[string]interface{}{"type": "string", "description": "Vault name (default: default)"},
		},
	}
	s.AddTool(vaultList, vaultListHandler)

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

	// Tool: identity_info
	identityInfo := mcp.NewTool("identity_info",
		mcp.WithDescription("Show details about a local identity"),
	)
	identityInfo.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"name": map[string]interface{}{"type": "string", "description": "Identity name"},
		},
		Required: []string{"name"},
	}
	s.AddTool(identityInfo, identityInfoHandler)

	// Tool: identity_rename
	identityRename := mcp.NewTool("identity_rename",
		mcp.WithDescription("Rename a local identity"),
	)
	identityRename.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"old": map[string]interface{}{"type": "string", "description": "Old name"},
			"new": map[string]interface{}{"type": "string", "description": "New name"},
		},
		Required: []string{"old", "new"},
	}
	s.AddTool(identityRename, identityRenameHandler)

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

	// Tool: tunnel_start
	tunnelStart := mcp.NewTool("tunnel_start",
		mcp.WithDescription("Provision a Post-Quantum L4 tunnel and SOCKS5 gateway"),
	)
	tunnelStart.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"remote":    map[string]interface{}{"type": "string", "description": "Remote PQC Tunnel endpoint (host:port)"},
			"port":      map[string]interface{}{"type": "integer", "description": "Local SOCKS5 proxy port (default 1080)"},
			"use_yamux": map[string]interface{}{"type": "boolean", "description": "Use TCP+Yamux mode"},
			"p2p_mode":  map[string]interface{}{"type": "boolean", "description": "Use libp2p for P2P mode"},
			"p2p_addr":  map[string]interface{}{"type": "string", "description": "Remote P2P Multiaddr"},
		},
	}
	s.AddTool(tunnelStart, tunnelStartHandler)

	// Tool: tunnel_stop
	tunnelStop := mcp.NewTool("tunnel_stop",
		mcp.WithDescription("Terminate the active PQC tunnel"),
	)
	tunnelStop.InputSchema = mcp.ToolInputSchema{
		Type:       "object",
		Properties: map[string]interface{}{},
	}
	s.AddTool(tunnelStop, tunnelStopHandler)

	// Tool: tunnel_status
	tunnelStatus := mcp.NewTool("tunnel_status",
		mcp.WithDescription("Retrieve status of the active tunnel"),
	)
	tunnelStatus.InputSchema = mcp.ToolInputSchema{
		Type:       "object",
		Properties: map[string]interface{}{},
	}
	s.AddTool(tunnelStatus, tunnelStatusHandler)

	return s
}

func vaultGetHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	service := request.GetString("service", "")
	_ = request.GetString("vault", "default")

	// Get master passphrase from environment (Agent convention)
	passRaw := viper.GetString("passphrase")
	if passRaw == "" {
		return mcp.NewToolResultError(`{"error":"authentication failed: passphrase required via MAKNOON_PASSPHRASE","code":401}`), nil
	}
	passphrase := []byte(passRaw)

	entry, err := engine.VaultGet(nil, "", service, passphrase, "")
	if err != nil {
		return formatError(err, "vault_get")
	}

	if entry == nil {
		return mcp.NewToolResultError(`{"error":"service not found","code":404}`), nil
	}

	res := struct {
		Service  string `json:"service"`
		Username string `json:"username"`
		Password string `json:"password"`
		URL      string `json:"url,omitempty"`
		Note     string `json:"note,omitempty"`
	}{
		Service:  entry.Service,
		Username: entry.Username,
		Password: string(entry.Password),
		URL:      entry.URL,
		Note:     entry.Note,
	}
	crypto.SafeClear(entry.Password)
	raw, _ := json.Marshal(res)
	return mcp.NewToolResultText(string(raw)), nil
}

func vaultSetHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	service := request.GetString("service", "")
	password := request.GetString("password", "")
	username := request.GetString("username", "")
	_ = request.GetString("vault", "default")

	// Get master passphrase from environment
	passRaw := viper.GetString("passphrase")
	if passRaw == "" {
		return mcp.NewToolResultError(`{"error":"authentication failed: passphrase required via MAKNOON_PASSPHRASE","code":401}`), nil
	}
	passphrase := []byte(passRaw)

	entry := &crypto.VaultEntry{
		Service:  service,
		Username: username,
		Password: []byte(password),
	}

	err := engine.VaultSet(nil, "", entry, passphrase, "")
	crypto.SafeClear(entry.Password)
	if err != nil {
		return formatError(err, "vault_set")
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"status":"success","service":"%s"}`, service)), nil
}

func encryptHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := request.GetString("input", "")
	output := request.GetString("output", "")
	pubKeyPath := request.GetString("public_key", "")

	// 1. Resolve keys if needed
	var pubKey []byte
	if pubKeyPath != "" {
		// Use core identity manager for resolution
		im := crypto.NewIdentityManager()
		base, _, err := im.ResolveBaseKeyPath(pubKeyPath)
		if err != nil {
			return formatError(err, "encrypt_file")
		}
		pk, err := os.ReadFile(base + ".kem.pub")
		if err != nil {
			// Try without suffix if it was already a full path
			pk, err = os.ReadFile(pubKeyPath)
			if err != nil {
				return formatError(err, "encrypt_file")
			}
		}
		pubKey = pk
	}

	passRaw := viper.GetString("passphrase")
	if passRaw == "" && pubKeyPath == "" {
		return mcp.NewToolResultError(`{"error":"authentication failed: passphrase required via MAKNOON_PASSPHRASE (or use public_key)","code":401}`), nil
	}
	passphrase := []byte(passRaw)

	opts := crypto.Options{
		Passphrase:  passphrase,
		Recipients:  [][]byte{pubKey},
		Concurrency: engine.GetConfig().AgentLimits.MaxWorkers,
	}

	// 2. Open output file
	outF, err := os.Create(output)
	if err != nil {
		return formatError(err, "encrypt_file")
	}
	defer outF.Close()

	// 3. Protect
	flags, err := engine.Protect(nil, input, nil, outF, opts)
	if err != nil {
		return formatError(err, "encrypt_file")
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"status":"success","path":"%s","flags":%d}`, output, flags)), nil
}

func decryptHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := request.GetString("input", "")
	output := request.GetString("output", "")
	privKeyPath := request.GetString("private_key", "")

	// 1. Resolve keys
	passRaw := viper.GetString("passphrase")
	if passRaw == "" && privKeyPath == "" {
		return mcp.NewToolResultError(`{"error":"authentication failed: passphrase required via MAKNOON_PASSPHRASE (or provide private_key)","code":401}`), nil
	}
	passphrase := []byte(passRaw)

	var privKey []byte
	if privKeyPath != "" {
		im := crypto.NewIdentityManager()
		base, _, err := im.ResolveBaseKeyPath(privKeyPath)
		if err != nil {
			return formatError(err, "decrypt_file")
		}
		pk, err := im.LoadPrivateKey(base+".kem.key", passphrase, "", false)
		if err != nil {
			return formatError(err, "decrypt_file")
		}
		privKey = pk
		defer crypto.SafeClear(privKey)
	}

	opts := crypto.Options{
		Passphrase:      passphrase,
		LocalPrivateKey: privKey,
		Concurrency:     engine.GetConfig().AgentLimits.MaxWorkers,
	}

	// 2. Open input
	inF, err := os.Open(input)
	if err != nil {
		return formatError(err, "decrypt_file")
	}
	defer inF.Close()

	// 3. Unprotect
	var outW io.Writer
	if output == "-" {
		// Caution: stdout might be used for MCP comms, but inToolResultText is safe.
		// However, returning raw bytes via MCP text is better than actual os.Stdout.
		var buf bytes.Buffer
		outW = &buf
		_, err = engine.Unprotect(nil, inF, outW, "", opts)
		if err != nil {
			return formatError(err, "decrypt_file")
		}
		return mcp.NewToolResultText(buf.String()), nil
	}

	_, err = engine.Unprotect(nil, inF, nil, output, opts)
	if err != nil {
		return formatError(err, "decrypt_file")
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"status":"success","path":"%s"}`, output)), nil
}

func genPasswordHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	length := request.GetInt("length", 32)
	noSymbols := request.GetBool("no_symbols", false)

	p, err := engine.GeneratePassword(nil, length, noSymbols)
	if err != nil {
		return formatError(err, "gen_password")
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"password":"%s"}`, p)), nil
}

func genPassphraseHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	words := request.GetInt("words", 4)
	separator := request.GetString("separator", "-")

	p, err := engine.GeneratePassphrase(nil, words, separator)
	if err != nil {
		return formatError(err, "gen_passphrase")
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"passphrase":"%s"}`, p)), nil
}

func inspectHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path := request.GetString("path", "")
	stealth := request.GetBool("stealth", false)

	f, err := os.Open(path)
	if err != nil {
		return formatError(err, "inspect_file")
	}
	defer f.Close()

	magic, profileID, flags, _, err := crypto.ReadHeader(f, stealth)
	if err != nil {
		return formatError(err, "inspect_file")
	}

	res := map[string]interface{}{
		"magic":      magic,
		"profile_id": profileID,
		"flags":      flags,
	}
	raw, _ := json.Marshal(res)
	return mcp.NewToolResultText(string(raw)), nil
}

func sendHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path := request.GetString("path", "")
	text := request.GetString("text", "")
	publicKeyPath := request.GetString("public_key", "")
	stealth := request.GetBool("stealth", false)
	rendURL := request.GetString("rendezvous_url", "")
	transit := request.GetString("transit_relay", "")

	var inputName string
	var inputReader io.Reader
	var isDir bool

	if text != "" {
		inputReader = strings.NewReader(text)
		inputName = "text-message"
	} else if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return formatError(err, "send_file")
		}
		defer f.Close()
		inputReader = f
		inputName = filepath.Base(path)
		fi, _ := f.Stat()
		isDir = fi.IsDir()
	} else {
		return mcp.NewToolResultError("Either 'path' or 'text' must be provided"), nil
	}

	var pubKey []byte
	if publicKeyPath != "" {
		im := crypto.NewIdentityManager()
		pk, err := im.ResolvePublicKey(publicKeyPath, false)
		if err != nil {
			return formatError(err, "send_file")
		}
		pubKey = pk
	}

	passRaw := viper.GetString("passphrase")
	if passRaw == "" {
		return mcp.NewToolResultError(`{"error":"authentication failed: passphrase required via MAKNOON_PASSPHRASE","code":401}`), nil
	}
	passphrase := []byte(passRaw)

	opts := crypto.P2PSendOptions{
		Passphrase:    passphrase,
		PublicKey:     pubKey,
		Stealth:       stealth,
		IsDirectory:   isDir,
		RendezvousURL: rendURL,
		TransitRelay:  transit,
	}

	ectx := crypto.NewEngineContext(ctx, nil, engine.GetPolicy())
	code, _, err := engine.P2PSend(ectx, inputName, inputReader, opts)
	if err != nil {
		return formatError(err, "send_file")
	}

	// For MCP tools, we usually want to return the code immediately,
	// but the transfer needs to stay alive until the peer connects.
	// Since MCP tool calls are synchronous, we'll wait for the completion or a timeout.
	// In a real production system, this might be handled via a background process and a separate 'p2p_status' tool.
	// For now, we'll wait for the 'success' or 'error' phase.

	// Actually, the AI needs the code to share it. If we wait, the AI can't get the code until it's finished.
	// RESOLUTION: Return the code immediately. The transfer will continue in the background until the context (ctx) is canceled.
	// Wait, engine.P2PSend starts a goroutine to monitor wStatus.

	res := map[string]string{
		"code":   code,
		"status": "established",
	}
	if len(passphrase) > 0 {
		res["passphrase"] = string(passphrase)
	}

	raw, _ := json.Marshal(res)
	return mcp.NewToolResultText(string(raw)), nil
}

func receiveHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	code := request.GetString("code", "")
	passphraseStr := request.GetString("passphrase", "")
	privKeyPath := request.GetString("private_key", "")
	output := request.GetString("output", "")
	stealth := request.GetBool("stealth", false)
	rendURL := request.GetString("rendezvous_url", "")
	transit := request.GetString("transit_relay", "")

	var privKey []byte
	var passphrase []byte

	if passphraseStr != "" {
		passphrase = []byte(passphraseStr)
	}

	if privKeyPath != "" {
		im := crypto.NewIdentityManager()
		resolved := im.ResolveKeyPath(privKeyPath, "")
		pk, err := im.LoadPrivateKey(resolved, passphrase, "", false)
		if err != nil {
			return formatError(err, "receive_file")
		}
		privKey = pk
		defer crypto.SafeClear(privKey)
	}

	opts := crypto.P2PReceiveOptions{
		Passphrase:    passphrase,
		PrivateKey:    privKey,
		Stealth:       stealth,
		OutputDir:     output,
		RendezvousURL: rendURL,
		TransitRelay:  transit,
	}

	ectx := crypto.NewEngineContext(ctx, nil, engine.GetPolicy())
	statusChan, err := engine.P2PReceive(ectx, code, opts)
	if err != nil {
		return formatError(err, "receive_file")
	}

	// Wait for completion (unlike Send, Receive needs to finish to show the output path)
	var lastStatus crypto.P2PStatus
	for s := range statusChan {
		lastStatus = s
		if s.Phase == "success" || s.Phase == "error" {
			break
		}
	}

	if lastStatus.Error != nil {
		return formatError(lastStatus.Error, "receive_file")
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"status":"success","path":"%s"}`, lastStatus.FileName)), nil
}

func startChatHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	session := crypto.NewChatSession("maknoon-mcp")
	code, err := session.StartHost(ctx)
	if err != nil {
		return formatError(err, "start_chat")
	}

	// We don't need to keep the session alive in this handler because
	// the purpose of 'start_chat' is just to generate a code for the user.
	// In a real P2P chat, the user would then join via the CLI.
	session.Close()

	return mcp.NewToolResultText(fmt.Sprintf(`{"status":"established","code":"%s"}`, code)), nil
}

func identityActiveHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	keys, err := engine.IdentityActive(&crypto.EngineContext{Context: ctx})
	if err != nil {
		return formatError(err, "identity_active")
	}

	fullKeys := make([]string, len(keys))
	for i, k := range keys {
		fullKeys[i] = k + ".kem.pub"
	}
	res := map[string]interface{}{
		"active_keys": fullKeys,
	}
	raw, _ := json.Marshal(res)
	return mcp.NewToolResultText(string(raw)), nil
}

func identitySplitHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := request.GetString("name", "")
	threshold := request.GetInt("threshold", 2)
	shares := request.GetInt("shares", 3)
	passphrase := request.GetString("passphrase", "")

	shards, err := engine.IdentitySplit(&crypto.EngineContext{Context: ctx}, name, threshold, shares, passphrase)
	if err != nil {
		return formatError(err, "identity_split")
	}

	res := map[string]interface{}{
		"status": "success",
		"shares": shards,
	}
	raw, _ := json.Marshal(res)
	return mcp.NewToolResultText(string(raw)), nil
}

func vaultListHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	vault := request.GetString("vault", "default")
	services, err := engine.VaultList(&crypto.EngineContext{Context: ctx}, "")
	if err != nil {
		return formatError(err, "vault_list")
	}

	res := map[string]interface{}{
		"vault":    vault,
		"services": services,
	}
	raw, _ := json.Marshal(res)
	return mcp.NewToolResultText(string(raw)), nil
}

func vaultSplitHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	threshold := request.GetInt("threshold", 2)
	shares := request.GetInt("shares", 3)
	passphrase := request.GetString("passphrase", "")

	shards, err := engine.VaultSplit(&crypto.EngineContext{Context: ctx}, "", threshold, shares, passphrase)
	if err != nil {
		return formatError(err, "vault_split")
	}

	res := map[string]interface{}{
		"status": "success",
		"shares": shards,
	}
	raw, _ := json.Marshal(res)
	return mcp.NewToolResultText(string(raw)), nil
}

func vaultRecoverHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	shards := request.GetStringSlice("shards", nil)
	output := request.GetString("output", "recovered")
	passphrase := request.GetString("passphrase", "")

	path, err := engine.VaultRecover(&crypto.EngineContext{Context: ctx}, shards, "", output, passphrase)
	if err != nil {
		return formatError(err, "vault_recover")
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"status":"success","path":"%s"}`, path)), nil
}

func identityCombineHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	shards := request.GetStringSlice("shards", nil)
	output := request.GetString("output", "restored_id")
	passphrase := request.GetString("passphrase", "")
	noPassword := request.GetBool("no_password", false)

	path, err := engine.IdentityCombine(&crypto.EngineContext{Context: ctx}, shards, output, passphrase, noPassword)
	if err != nil {
		return formatError(err, "identity_combine")
	}

	res := map[string]string{
		"status":    "success",
		"base_path": path,
	}
	raw, _ := json.Marshal(res)
	return mcp.NewToolResultText(string(raw)), nil
}

func identityPublishHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	handle := request.GetString("handle", "")
	name := request.GetString("name", "")
	nostr := request.GetBool("nostr", false)
	dns := request.GetBool("dns", false)
	local := request.GetBool("local", false)
	desec := request.GetBool("desec", false)
	desecToken := request.GetString("desec_token", "")

	opts := crypto.IdentityPublishOptions{
		Passphrase: viper.GetString("passphrase"),
		Name:       name,
		Nostr:      nostr,
		DNS:        dns,
		Local:      local,
		Desec:      desec,
		DesecToken: desecToken,
	}

	ectx := crypto.NewEngineContext(ctx, nil, engine.GetPolicy())
	err := engine.IdentityPublish(ectx, handle, opts)
	if err != nil {
		return formatError(err, "identity_publish")
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"status":"success","handle":"%s"}`, handle)), nil
}

func identityInfoHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := request.GetString("name", "")
	path, err := engine.IdentityInfo(&crypto.EngineContext{Context: ctx}, name)
	if err != nil {
		return formatError(err, "identity_info")
	}

	res := map[string]string{
		"identity": name,
		"path":     path,
	}
	raw, _ := json.Marshal(res)
	return mcp.NewToolResultText(string(raw)), nil
}

func identityRenameHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	oldName := request.GetString("old", "")
	newName := request.GetString("new", "")

	err := engine.IdentityRename(&crypto.EngineContext{Context: ctx}, oldName, newName)
	if err != nil {
		return formatError(err, "identity_rename")
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"status":"success","from":"%s","to":"%s"}`, oldName, newName)), nil
}

func contactAddHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	petname := request.GetString("petname", "")
	kemPub := request.GetString("kem_pub", "")
	sigPub := request.GetString("sig_pub", "")
	note := request.GetString("note", "")

	err := engine.ContactAdd(&crypto.EngineContext{Context: ctx}, petname, kemPub, sigPub, note)
	if err != nil {
		return formatError(err, "contact_add")
	}

	return mcp.NewToolResultText(fmt.Sprintf(`{"status":"success","petname":"%s"}`, petname)), nil
}

func contactListHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	contacts, err := engine.ContactList(&crypto.EngineContext{Context: ctx})
	if err != nil {
		return formatError(err, "contact_list")
	}

	raw, _ := json.Marshal(contacts)
	return mcp.NewToolResultText(string(raw)), nil
}

func profilesListHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	conf := engine.GetConfig()
	var profiles []string
	for name := range conf.Profiles {
		profiles = append(profiles, name)
	}

	res := map[string]interface{}{
		"custom_profiles": profiles,
		"built_in":        []string{"nist", "aes", "conservative"},
	}
	raw, _ := json.Marshal(res)
	return mcp.NewToolResultText(string(raw)), nil
}

func profilesGenHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := request.GetString("name", "")
	if name == "" {
		return mcp.NewToolResultError("Profile name is required"), nil
	}

	// 1. Find available ID
	conf := engine.GetConfig()
	usedIDs := make(map[byte]bool)
	for _, p := range conf.Profiles {
		usedIDs[p.ID()] = true
	}
	var nextID byte
	for i := byte(4); i < 128; i++ {
		if !usedIDs[i] {
			nextID = i
			break
		}
	}

	if nextID == 0 {
		return mcp.NewToolResultError("No available profile IDs (limit reached)"), nil
	}

	// 2. Generate and validate
	dp := engine.GenerateRandomProfile(nil, nextID)
	if err := engine.ValidateProfile(nil, dp); err != nil {
		return formatError(err, "profiles_gen")
	}

	// 3. Register via engine (Handles policy check internally)
	if err := engine.RegisterProfile(nil, name, dp); err != nil {
		if crypto.As(err, new(*crypto.ErrPolicyViolation)) {
			// Return ephemeral JSON for the AI to use
			res := map[string]interface{}{
				"status":            "success",
				"ephemeral_profile": dp,
				"warning":           "could not save to config (policy restriction)",
			}
			raw, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(raw)), nil
		}
		return formatError(err, "profiles_gen")
	}

	res := map[string]interface{}{
		"status": "success",
		"name":   name,
		"id":     nextID,
	}
	raw, _ := json.Marshal(res)
	return mcp.NewToolResultText(string(raw)), nil
}

func tunnelStartHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	remote := request.GetString("remote", "")
	port := request.GetInt("port", 1080)
	useYamux := request.GetBool("use_yamux", false)
	p2pMode := request.GetBool("p2p_mode", false)
	p2pAddr := request.GetString("p2p_addr", "")

	opts := tunnel.TunnelOptions{
		RemoteEndpoint: remote,
		LocalProxyPort: port,
		UseYamux:       useYamux,
		P2PMode:        p2pMode,
		P2PAddr:        p2pAddr,
	}

	status, err := engine.TunnelStart(&crypto.EngineContext{Context: ctx}, opts)
	if err != nil {
		return formatError(err, "tunnel_start")
	}

	raw, _ := json.Marshal(status)
	return mcp.NewToolResultText(string(raw)), nil
}

func tunnelStopHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	err := engine.TunnelStop(&crypto.EngineContext{Context: ctx})
	if err != nil {
		return formatError(err, "tunnel_stop")
	}
	return mcp.NewToolResultText(`{"status":"stopped"}`), nil
}

func tunnelStatusHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	status, err := engine.TunnelStatus(&crypto.EngineContext{Context: ctx})
	if err != nil {
		return formatError(err, "tunnel_status")
	}
	raw, _ := json.Marshal(status)
	return mcp.NewToolResultText(string(raw)), nil
}
