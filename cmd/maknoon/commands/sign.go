package commands

import (
	"bytes"
	"fmt"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// SignCmd returns the cobra command for signing files.
func SignCmd() *cobra.Command {
	var sigKeyPath string
	var passphrase string

	cmd := &cobra.Command{
		Use:   "sign [file]",
		Short: "Sign a file using an ML-DSA private key",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			filePath := args[0]
			data, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}

			resolvedPath := crypto.ResolveKeyPath(sigKeyPath, "MAKNOON_PRIVATE_KEY")
			if resolvedPath == "" {
				err := fmt.Errorf("signing key required (use --private-key or MAKNOON_PRIVATE_KEY)")
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}

			keyBytes, err := os.ReadFile(resolvedPath)
			if err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}

			// Unlock logic
			if len(keyBytes) > 4 && string(keyBytes[:4]) == crypto.MagicHeader {
				password := []byte(passphrase)
				if len(password) == 0 {
					if env := os.Getenv("MAKNOON_PASSPHRASE"); env != "" {
						password = []byte(env)
					}
				}
				if len(password) == 0 {
					err := fmt.Errorf("private key is encrypted; provide passphrase via --passphrase or MAKNOON_PASSPHRASE")
					if JSONOutput {
						printErrorJSON(err)
						return nil
					}
					return err
				}

				var unlockedKey bytes.Buffer
				if _, err := crypto.DecryptStream(bytes.NewReader(keyBytes), &unlockedKey, password, 1, false); err != nil {
					err := fmt.Errorf("failed to unlock signing key: %w", err)
					if JSONOutput {
						printErrorJSON(err)
						return nil
					}
					return err
				}
				keyBytes = unlockedKey.Bytes()
				defer crypto.SafeClear(keyBytes)
			}

			sig, err := crypto.SignData(data, keyBytes)
			if err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}

			sigFile := filePath + ".sig"
			if err := os.WriteFile(sigFile, sig, 0644); err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}

			if JSONOutput {
				printJSON(map[string]string{"status": "success", "signature": sigFile})
			} else {
				fmt.Printf("File signed successfully. Signature saved to %s\n", sigFile)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&sigKeyPath, "private-key", "k", "", "Path to the ML-DSA private key")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase to unlock the private key")
	return cmd
}
