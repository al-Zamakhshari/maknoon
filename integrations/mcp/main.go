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
	s := server.NewMCPServer(
		"Maknoon PQC Server",
		"1.1.6",
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

	// Tool: identity_active
	identityActive := mcp.NewTool("identity_active",
		mcp.WithDescription("List available Post-Quantum public keys on this system"),
	)
	identityActive.InputSchema = mcp.ToolInputSchema{
		Type:       "object",
		Properties: map[string]interface{}{},
	}
	s.AddTool(identityActive, identityActiveHandler)

	if err := server.ServeStdio(s); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

func getMaknoonBinary() string {
	if b := os.Getenv("MAKNOON_BINARY"); b != "" {
		return b
	}
	return "maknoon"
}

func vaultGetHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	service := request.GetString("service", "")
	vault := request.GetString("vault", "default")

	cmd := exec.CommandContext(ctx, getMaknoonBinary(), "vault", "get", service, "--vault", vault, "--json")
	cmd.Env = append(os.Environ(), "MAKNOON_JSON=1")

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
	cmd.Env = append(os.Environ(), "MAKNOON_JSON=1", "MAKNOON_PASSWORD="+password)

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
	cmd.Env = append(os.Environ(), "MAKNOON_JSON=1")

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Encryption failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}

func identityActiveHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cmd := exec.CommandContext(ctx, getMaknoonBinary(), "identity", "active", "--json")
	cmd.Env = append(os.Environ(), "MAKNOON_JSON=1")

	out, err := cmd.CombinedOutput()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Identity active failed: %s", string(out))), nil
	}

	return mcp.NewToolResultText(string(out)), nil
}
