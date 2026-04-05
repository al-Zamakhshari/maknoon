package commands

import (
	"bytes"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/username/maknoon/pkg/crypto"
	"golang.org/x/term"
)

func KeygenCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a Post-Quantum (ML-KEM/Kyber1024) keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print("Enter passphrase to protect your private key (leave empty for no protection): ")
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

			if len(password) > 0 {
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
			}

			fmt.Println("Generating bleeding-edge Post-Quantum keypair (Kyber1024)...")
			pub, priv, err := crypto.GeneratePQKeyPair()
			if err != nil {
				return fmt.Errorf("failed to generate keypair: %w", err)
			}
			defer func() {
				for i := range priv {
					priv[i] = 0
				}
			}()

			// If password provided, encrypt the private key
			var finalPriv []byte = priv
			if len(password) > 0 {
				var b bytes.Buffer
				if err := crypto.EncryptStream(bytes.NewReader(priv), &b, password); err != nil {
					return fmt.Errorf("failed to encrypt private key: %w", err)
				}
				finalPriv = b.Bytes()
				defer func() {
					for i := range finalPriv {
						finalPriv[i] = 0
					}
				}()
			}

			pubFile := output + ".pub"
			privFile := output
			if output == "" {
				pubFile = "maknoon.pub"
				privFile = "maknoon.key"
			}

			// Write Private Key (Carefully preserved)
			if err := os.WriteFile(privFile, finalPriv, 0600); err != nil {
				return fmt.Errorf("failed to write private key: %w", err)
			}

			// Write Public Key
			if err := os.WriteFile(pubFile, pub, 0644); err != nil {
				return fmt.Errorf("failed to write public key: %w", err)
			}

			fmt.Printf("Success! Keypair generated:\n")
			fmt.Printf("  - Private Key: %s (Keep this secret!)\n", privFile)
			fmt.Printf("  - Public Key:  %s (Share this with others)\n", pubFile)
			
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Base name for the keys (e.g., 'id_maknoon')")
	return cmd
}
