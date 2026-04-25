// Package main is the entry point for the maknoon CLI tool.
package main

import (
	"os"

	"github.com/al-Zamakhshari/maknoon/cmd/maknoon/commands"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:     "maknoon",
		Version: version,
		Short:   "Maknoon (مكنون): Enterprise-Grade Post-Quantum Encryption Engine",
		Long: `Maknoon is a high-performance cryptographic engine and MCP server designed
to secure data against classical and quantum threats using NIST-standardized
Post-Quantum Cryptography (PQC).`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// Initialize Viper for flag binding
			commands.SetupViper()

			// Bind persistent flags to viper
			_ = viper.BindPFlag("json", cmd.Flags().Lookup("json"))

			if err := commands.InitEngine(); err != nil {
				return err
			}

			// Silence Cobra boilerplate if outputting machine-readable results
			if viper.GetBool("json") || viper.GetString("agent_mode") == "1" {
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
			}
			commands.GlobalContext.JSONWriter = commands.JSONWriter

			return nil
		},
	}

	rootCmd.PersistentFlags().BoolVar(&commands.JSONOutput, "json", false, "Output results in JSON format")

	// Define Command Groups
	coreGroup := &cobra.Group{ID: "core", Title: "Cryptographic Operations:"}
	identityGroup := &cobra.Group{ID: "identity", Title: "Identity & Trust:"}
	securityGroup := &cobra.Group{ID: "security", Title: "Security & Integrity:"}
	utilsGroup := &cobra.Group{ID: "utils", Title: "Enterprise & System:"}

	rootCmd.AddGroup(coreGroup, identityGroup, securityGroup, utilsGroup)

	// Helper to add command to group and root
	addCommand := func(c *cobra.Command, groupID string) {
		c.GroupID = groupID
		rootCmd.AddCommand(c)
	}

	// Assign Commands to Groups
	addCommand(commands.EncryptCmd(), "core")
	addCommand(commands.DecryptCmd(), "core")
	addCommand(commands.SendCmd(), "core")
	addCommand(commands.ReceiveCmd(), "core")
	addCommand(commands.ChatCmd(), "core")
	addCommand(commands.TunnelCmd(), "core")
	addCommand(commands.InfoCmd(), "core")

	addCommand(commands.KeygenCmd(), "identity")
	addCommand(commands.IdentityCmd(), "identity")
	addCommand(commands.ContactCmd(), "identity")

	addCommand(commands.SignCmd(), "security")
	addCommand(commands.VerifyCmd(), "security")

	addCommand(commands.VaultCmd(), "utils")
	addCommand(commands.GenCmd(), "utils")
	addCommand(commands.ConfigCmd(), "utils")
	addCommand(commands.ProfilesCmd(), "utils")
	addCommand(commands.MCPServerCmd(), "utils")

	// Automation-only commands (Hidden from standard help)
	schemaCmd := commands.SchemaCmd()
	schemaCmd.Hidden = true
	rootCmd.AddCommand(schemaCmd)

	manCmd := commands.ManCmd()
	manCmd.Hidden = true
	rootCmd.AddCommand(manCmd)

	mcpCmd := commands.MCPServerCmd()
	mcpCmd.Hidden = true
	rootCmd.AddCommand(mcpCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
