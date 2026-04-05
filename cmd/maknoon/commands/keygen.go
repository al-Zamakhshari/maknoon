package commands

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/a-khallaf/maknoon/pkg/crypto"
	"golang.org/x/term"
)

func KeygenCmd() *cobra.Command {
	var output string
	var noPassword bool
	var passphrase string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a Post-Quantum (KEM & SIG) identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			var password []byte
			var err error

			if !noPassword {
				if passphrase != "" {
					password = []byte(passphrase)
				} else if envPass := os.Getenv("MAKNOON_PASSPHRASE"); envPass != "" {
					password = []byte(envPass)
				} else {
					fmt.Print("Enter passphrase to protect your private keys: ")
					p, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil { return err }
					password = p

					if len(password) > 0 {
						fmt.Print("Confirm passphrase: ")
						confirm, _ := term.ReadPassword(int(os.Stdin.Fd()))
						fmt.Println()
						if string(password) != string(confirm) {
							return fmt.Errorf("passphrases do not match")
						}
					}
				}
			}

			if len(password) > 0 {
				defer func() { for i := range password { password[i] = 0 } }()
			}

			fmt.Println("Generating bleeding-edge Post-Quantum identity (Kyber1024 + ML-DSA-87)...")
			kemPub, kemPriv, sigPub, sigPriv, err := crypto.GeneratePQKeyPair()
			if err != nil {
				return fmt.Errorf("failed to generate keypairs: %w", err)
			}
			defer func() {
				for i := range kemPriv { kemPriv[i] = 0 }
				for i := range sigPriv { sigPriv[i] = 0 }
			}()

			home, _ := os.UserHomeDir()
			keysDir := filepath.Join(home, ".maknoon", "keys")
			os.MkdirAll(keysDir, 0700)

			baseName := "id_maknoon"
			if output != "" {
				baseName = output
			}
			
			// Determine final paths
			basePath := filepath.Join(keysDir, baseName)
			if output != "" && (filepath.IsAbs(output) || strings.Contains(output, string(os.PathSeparator))) {
				basePath = output
			}

			writeKey := func(path string, data []byte, isPrivate bool) error {
				finalData := data
				if isPrivate && len(password) > 0 {
					var b bytes.Buffer
					if err := crypto.EncryptStream(bytes.NewReader(data), &b, password, crypto.FlagNone); err != nil {
						return err
					}
					finalData = b.Bytes()
				}
				mode := os.FileMode(0644)
				if isPrivate { mode = 0600 }
				return os.WriteFile(path, finalData, mode)
			}

			// Save KEM Keys
			if err := writeKey(basePath+".kem.key", kemPriv, true); err != nil { return err }
			if err := writeKey(basePath+".kem.pub", kemPub, false); err != nil { return err }

			// Save SIG Keys
			if err := writeKey(basePath+".sig.key", sigPriv, true); err != nil { return err }
			if err := writeKey(basePath+".sig.pub", sigPub, false); err != nil { return err }

			fmt.Printf("Success! Identity generated in %s\n", filepath.Dir(basePath))
			fmt.Printf("  - Encryption Keys: %s.kem.{key,pub}\n", baseName)
			fmt.Printf("  - Signing Keys:    %s.sig.{key,pub}\n", baseName)
			
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Base name or path for the keys")
	cmd.Flags().BoolVarP(&noPassword, "no-password", "n", false, "Generate unprotected keys (automation mode)")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase to protect the keys")
	return cmd
}
