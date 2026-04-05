package main

import (
	"os"
	
	"github.com/spf13/cobra"
	"github.com/a-khallaf/maknoon/cmd/maknoon/commands"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "maknoon",
		Short: "Maknoon (مكنون): A versatile, ultra-efficient CLI encryption tool.",
		Long:  `Maknoon uses bleeding-edge hybrid cryptography to protect your files carefully.`,
	}

	rootCmd.AddCommand(commands.EncryptCmd())
	rootCmd.AddCommand(commands.DecryptCmd())
	rootCmd.AddCommand(commands.KeygenCmd())
	rootCmd.AddCommand(commands.GenCmd())
	rootCmd.AddCommand(commands.VaultCmd())
	rootCmd.AddCommand(commands.SignCmd())
	rootCmd.AddCommand(commands.VerifyCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
