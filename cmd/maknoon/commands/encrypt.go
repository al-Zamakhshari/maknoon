package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/username/maknoon/pkg/crypto"
	"golang.org/x/term"
)

func EncryptCmd() *cobra.Command {
	var output string
	var pubKeyPath string

	cmd := &cobra.Command{
		Use:   "encrypt [file]",
		Short: "Encrypt a file symmetrically (passphrase) or asymmetrically (public key)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			inputFile := args[0]
			
			in, err := os.Open(inputFile)
			if err != nil {
				return fmt.Errorf("failed to open input file: %w", err)
			}
			defer in.Close()

			info, err := in.Stat()
			if err != nil {
				return err
			}

			outPath := output
			if outPath == "" {
				outPath = inputFile + ".makn"
			}
			out, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}
			defer out.Close()

			// Asymmetric Mode (Public Key)
			if pubKeyPath != "" {
				pubKeyBytes, err := os.ReadFile(pubKeyPath)
				if err != nil {
					return fmt.Errorf("failed to read public key: %w", err)
				}
				fmt.Printf("Encrypting '%s' using public key '%s'...\n", inputFile, pubKeyPath)

				bar := progressbar.DefaultBytes(info.Size(), "preserving")
				if err := crypto.EncryptStreamWithPublicKey(io.TeeReader(in, bar), out, pubKeyBytes); err != nil {
					return fmt.Errorf("encryption failed: %w", err)
				}
			} else {
				// Symmetric Mode (Passphrase)
				fmt.Print("Enter passphrase: ")
				password, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					return err
				}
				defer func() {
					for i := range password {
						password[i] = 0
					}
				}()

				fmt.Print("Confirm passphrase: ")
				confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					return err
				}
				defer func() {
					for i := range confirm {
						confirm[i] = 0
					}
				}()
				if string(password) != string(confirm) {
					return fmt.Errorf("passphrases do not match")
				}

				fmt.Printf("Encrypting '%s' using passphrase...\n", inputFile)

				bar := progressbar.DefaultBytes(info.Size(), "preserving")
				if err := crypto.EncryptStream(io.TeeReader(in, bar), out, password); err != nil {
					return fmt.Errorf("encryption failed: %w", err)
				}
			}


			fmt.Println("\nEncryption successful! Data is now Maknoon (carefully preserved).")
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (default is input.makn)")
	cmd.Flags().StringVarP(&pubKeyPath, "pubkey", "p", "", "Path to the recipient's public key for asymmetric encryption")
	return cmd
}
