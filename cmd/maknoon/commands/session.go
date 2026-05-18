package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// SessionCmd returns the session management command group.
func SessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Session key utilities (derive, inspect)",
		Long:  "Manage pre-derived session keys to skip per-file KDF overhead when encrypting many files.",
	}
	cmd.AddCommand(sessionDeriveCmd())
	return cmd
}

func sessionDeriveCmd() *cobra.Command {
	var passphrase string

	cmd := &cobra.Command{
		Use:   "derive",
		Short: "Derive a session key from a passphrase and print it as hex",
		Long: `Derives a 32-byte AES key from a passphrase using Argon2id and prints it as hex.
Use the output with --session-key on subsequent encrypt/decrypt calls to skip
the per-file KDF cost (~26ms per file) when processing many files.

Example:
  KEY=$(maknoon session derive -s mypassphrase)
  maknoon encrypt --session-key "$KEY" file1.txt
  maknoon encrypt --session-key "$KEY" file2.txt`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := GlobalContext.UI.GetPresenter()
			pw := []byte(passphrase)

			if len(pw) == 0 {
				if !term.IsTerminal(0) {
					return fmt.Errorf("--passphrase is required (or use an interactive terminal)")
				}
				fmt.Fprint(cmd.ErrOrStderr(), "Passphrase: ")
				var err error
				pw, err = term.ReadPassword(0)
				fmt.Fprintln(cmd.ErrOrStderr())
				if err != nil {
					return fmt.Errorf("failed to read passphrase: %w", err)
				}
			}
			defer crypto.SafeClear(pw)

			key, salt, err := crypto.DeriveSessionKey(pw)
			if err != nil {
				p.RenderError(err)
				return err
			}
			defer crypto.SafeClear(key)

			if GlobalContext.UI.JSON {
				p.RenderSuccess(map[string]string{
					"key":  hex.EncodeToString(key),
					"salt": hex.EncodeToString(salt),
				})
			} else {
				fmt.Println(hex.EncodeToString(key))
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase to derive from")
	return cmd
}
