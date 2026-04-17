// Package main is the entry point for the maknoon CLI tool.
package main

import (
	"os"

	"github.com/al-Zamakhshari/maknoon/cmd/maknoon/commands"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "maknoon",
		Short: "Maknoon (مكنون): A versatile, ultra-efficient CLI encryption tool.",
		Long:  `Maknoon uses bleeding-edge hybrid cryptography to protect your files carefully.`,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			if commands.JSONOutput || os.Getenv("MAKNOON_JSON") == "1" {
				commands.JSONOutput = true
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
			}
		},
	}

	rootCmd.PersistentFlags().BoolVar(&commands.JSONOutput, "json", false, "Output results in JSON format")

	rootCmd.AddCommand(commands.EncryptCmd())
	rootCmd.AddCommand(commands.DecryptCmd())
	rootCmd.AddCommand(commands.KeygenCmd())
	rootCmd.AddCommand(commands.ProfilesCmd())
	rootCmd.AddCommand(commands.GenCmd())
	rootCmd.AddCommand(commands.VaultCmd())
	rootCmd.AddCommand(commands.SignCmd())
	rootCmd.AddCommand(commands.VerifyCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
