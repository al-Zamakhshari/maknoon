package commands

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/username/maknoon/pkg/crypto"
	"golang.org/x/term"
)

func KeygenCmd() *cobra.Command {
	var output string
	var noPassword bool
	var passphrase string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a Post-Quantum (ML-KEM/Kyber1024) keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			var password []byte
			var err error

			if !noPassword {
				// 1. Check Flag
				if passphrase != "" {
					password = []byte(passphrase)
				}
				
				// 2. Check Environment Variable
				if len(password) == 0 {
					if envPass := os.Getenv("MAKNOON_PASSPHRASE"); envPass != "" {
						password = []byte(envPass)
					}
				}

				// 3. Fallback to Interactive
				if len(password) == 0 {
					fmt.Print("Enter passphrase to protect your private key (leave empty for no protection): ")
					p, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil {
						return err
					}
					password = p

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
				}
			} else {
				fmt.Println("Generating unprotected keypair (Automation Mode)...")
			}

			if len(password) > 0 {
				defer func() {
					for i := range password {
						password[i] = 0
					}
				}()
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

			// Handle Default Path logic
			home, _ := os.UserHomeDir()
			maknoonDir := filepath.Join(home, ".maknoon")
			os.MkdirAll(maknoonDir, 0700)

			var privFile, pubFile string
			if output == "" {
				privFile = filepath.Join(maknoonDir, "id_maknoon")
				pubFile = privFile + ".pub"
			} else {
				// If user provided a name/path, use it directly
				privFile = output
				pubFile = output + ".pub"
			}

			// If password provided, encrypt the private key
			var finalPriv []byte = priv
			if len(password) > 0 {
				var b bytes.Buffer
				if err := crypto.EncryptStream(bytes.NewReader(priv), &b, password, crypto.FlagNone); err != nil {
					return fmt.Errorf("failed to encrypt private key: %w", err)
				}
				finalPriv = b.Bytes()
				defer func() {
					for i := range finalPriv {
						finalPriv[i] = 0
					}
				}()
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
	cmd.Flags().BoolVarP(&noPassword, "no-password", "n", false, "Generate an unprotected private key (suitable for automation)")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase to protect the key (Avoid for security!)")
	return cmd
}
