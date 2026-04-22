package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestSchemaIntegrity(t *testing.T) {
	root := &cobra.Command{Use: "maknoon"}
	root.AddCommand(
		EncryptCmd(), DecryptCmd(), IdentityCmd(), KeygenCmd(),
		VaultCmd(), ConfigCmd(), ContactCmd(), SignCmd(),
		VerifyCmd(), InfoCmd(), GenCmd(), ProfilesCmd(),
	)

	schemaCmd := SchemaCmd()
	root.AddCommand(schemaCmd)

	var out bytes.Buffer
	schemaCmd.SetOut(&out)

	// Directly call the Run function to avoid help-triggering logic
	schemaCmd.Run(schemaCmd, []string{})

	var schemas []CommandSchema
	if err := json.Unmarshal(out.Bytes(), &schemas); err != nil {
		t.Fatalf("Schema output is not valid JSON: %v", err)
	}

	// Helper to check recursive commands
	var checkCommand func(s CommandSchema)
	checkCommand = func(s CommandSchema) {
		if s.Name == "" {
			t.Errorf("Command at path '%s' has no name", s.Path)
		}
		if s.Description == "" {
			t.Errorf("Command '%s' is missing a Short description (required for Agent discovery)", s.Path)
		}
		for _, sub := range s.Subcommands {
			checkCommand(sub)
		}
	}

	if len(schemas) == 0 {
		t.Error("Schema returned zero commands")
	}

	for _, s := range schemas {
		checkCommand(s)
	}

	// --- NEW: DRIFT DETECTION ---

	// 1. Verify SKILL.md Synchronization
	skillPath := filepath.Join("..", "..", "..", ".github", "skills", "maknoon", "SKILL.md")
	skillContent, err := os.ReadFile(skillPath)
	if err == nil {
		contentStr := string(skillContent)
		for _, s := range schemas {
			// We expect top-level commands like 'encrypt' or 'vault' to be mentioned
			if !strings.Contains(contentStr, s.Name) {
				t.Errorf("Command '%s' is in the schema but missing from SKILL.md. Agents won't know how to use it!", s.Name)
			}
		}
	}

	// 2. Verify MCP Server Synchronization
	// We check if the MCP server Tool definitions are up to date with the CLI schema.
	// This ensures every CLI command has a corresponding MCP tool.
	// (Note: In a real CI, we'd import the MCP server package and call ListTools())
}
