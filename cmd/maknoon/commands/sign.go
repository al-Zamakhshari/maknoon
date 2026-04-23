package commands

import (
	"fmt"
	"os"
	"strings"

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
			if err := validatePath(filePath); err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}
			data, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}

			m := crypto.NewIdentityManager()
			resolvedPath := m.ResolveKeyPath(sigKeyPath, "MAKNOON_PRIVATE_KEY")
			if resolvedPath == "" {
				err := fmt.Errorf("signing key required (use --private-key or MAKNOON_PRIVATE_KEY)")
				if JSONOutput {
					printErrorJSON(err)
					return err
				}
				return err
			}

			// Check for FIDO2 and get PIN if needed
			var pin string
			if _, err := os.Stat(strings.TrimSuffix(resolvedPath, ".key") + ".fido2"); err == nil {
				var err2 error
				pin, err2 = getPIN()
				if err2 != nil {
					return err2
				}
			}

			keyBytes, err := m.LoadPrivateKey(resolvedPath, []byte(passphrase), pin, false)
			if err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return err
				}
				return err
			}
			defer crypto.SafeClear(keyBytes)

			sig, err := crypto.SignData(data, keyBytes)
			if err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return err
				}
				return err
			}

			sigFile := filePath + ".sig"
			if err := validatePath(sigFile); err != nil {
				return err
			}
			if err := os.WriteFile(sigFile, sig, 0644); err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return err
				}
				return err
			}

			if JSONOutput {
				printJSON(crypto.CommonResult{
					Status:  "success",
					Message: fmt.Sprintf("Signature saved to %s", sigFile),
				})
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
