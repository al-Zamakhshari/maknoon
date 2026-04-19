// Package main is the entry point for the maknoon CLI tool.
package main

import (
	"os"

	"github.com/al-Zamakhshari/maknoon/cmd/maknoon/commands"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:     "maknoon",
		Version: version,
		Short:   "Maknoon (مكنون): A versatile, ultra-efficient CLI encryption tool.",
		Long:    `Maknoon uses bleeding-edge hybrid cryptography to protect your files carefully.`,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			// Auto-detect Agent mode: not a TTY and MAKNOON_AGENT_MODE env var is set
			isAgent := !term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("MAKNOON_AGENT_MODE") == "1"
			if commands.JSONOutput || os.Getenv("MAKNOON_JSON") == "1" || isAgent {
				commands.SetJSONOutput(true)
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
			}
			commands.GlobalContext.JSONWriter = commands.JSONWriter
		},
	}

	rootCmd.PersistentFlags().BoolVar(&commands.JSONOutput, "json", false, "Output results in JSON format")

	// Define Command Groups
	rootCmd.AddGroup(&cobra.Group{ID: "core", Title: "Core Commands:"})
	rootCmd.AddGroup(&cobra.Group{ID: "identity", Title: "Identity Management:"})
	rootCmd.AddGroup(&cobra.Group{ID: "security", Title: "Security & Integrity:"})
	rootCmd.AddGroup(&cobra.Group{ID: "utils", Title: "Utilities & Secrets:"})

	// Assign Commands to Groups
	encryptCmd := commands.EncryptCmd()
	encryptCmd.GroupID = "core"
	rootCmd.AddCommand(encryptCmd)

	decryptCmd := commands.DecryptCmd()
	decryptCmd.GroupID = "core"
	rootCmd.AddCommand(decryptCmd)

	sendCmd := commands.SendCmd()
	sendCmd.GroupID = "core"
	rootCmd.AddCommand(sendCmd)

	receiveCmd := commands.ReceiveCmd()
	receiveCmd.GroupID = "core"
	rootCmd.AddCommand(receiveCmd)

	infoCmd := commands.InfoCmd()
	infoCmd.GroupID = "core"
	rootCmd.AddCommand(infoCmd)

	keygenCmd := commands.KeygenCmd()
	keygenCmd.GroupID = "identity"
	rootCmd.AddCommand(keygenCmd)

	identityCmd := commands.IdentityCmd()
	identityCmd.GroupID = "identity"
	rootCmd.AddCommand(identityCmd)

	signCmd := commands.SignCmd()
	signCmd.GroupID = "security"
	rootCmd.AddCommand(signCmd)

	verifyCmd := commands.VerifyCmd()
	verifyCmd.GroupID = "security"
	rootCmd.AddCommand(verifyCmd)

	vaultCmd := commands.VaultCmd()
	vaultCmd.GroupID = "utils"
	rootCmd.AddCommand(vaultCmd)

	genCmd := commands.GenCmd()
	genCmd.GroupID = "utils"
	rootCmd.AddCommand(genCmd)

	profilesCmd := commands.ProfilesCmd()
	profilesCmd.GroupID = "utils"
	rootCmd.AddCommand(profilesCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
