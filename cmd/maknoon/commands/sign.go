package commands

import (
	"bytes"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/a-khallaf/maknoon/pkg/crypto"
)

func SignCmd() *cobra.Command {
	var sigKeyPath string
	var passphrase string

	cmd := &cobra.Command{
		Use:   "sign [file]",
		Short: "Sign a file using a Post-Quantum (ML-DSA) private key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]
			data, err := os.ReadFile(filePath)
			if err != nil { return err }

			resolvedPath := resolveKeyPath(sigKeyPath)
			if resolvedPath == "" {
				return fmt.Errorf("signing key required (use --private-key)")
			}

			keyBytes, err := os.ReadFile(resolvedPath)
			if err != nil { return err }

			// Unlock logic
			if len(keyBytes) > 4 && string(keyBytes[:4]) == crypto.MagicHeader {
				password := []byte(passphrase)
				if len(password) == 0 {
					if env := os.Getenv("MAKNOON_PASSPHRASE"); env != "" {
						password = []byte(env)
					}
				}
				if len(password) == 0 {
					return fmt.Errorf("private key is encrypted; provide passphrase via --passphrase or MAKNOON_PASSPHRASE")
				}
				
				var unlockedKey bytes.Buffer
				if _, err := crypto.DecryptStream(bytes.NewReader(keyBytes), &unlockedKey, password); err != nil {
					return fmt.Errorf("failed to unlock signing key: %w", err)
				}
				keyBytes = unlockedKey.Bytes()
				defer func() {
					for i := range keyBytes { keyBytes[i] = 0 }
				}()
			}

			sig, err := crypto.SignData(data, keyBytes)
			if err != nil { return err }

			sigFile := filePath + ".sig"
			if err := os.WriteFile(sigFile, sig, 0644); err != nil {
				return err
			}

			fmt.Printf("File signed successfully. Signature saved to %s\n", sigFile)
			return nil
		},
	}

	cmd.Flags().StringVarP(&sigKeyPath, "private-key", "k", "", "Path to the ML-DSA private key")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase to unlock the private key")
	return cmd
}
