package commands

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

const (
	lowerLetters = "abcdefghijklmnopqrstuvwxyz"
	upperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits       = "0123456789"
	symbols      = "!@#$%^&*()-_=+[]{}|;:,.<>?"
)

// GenCmd returns the cobra command for generating secure passwords.
func GenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate a high-entropy secure password or passphrase",
	}

	cmd.AddCommand(genPasswordCmd())
	cmd.AddCommand(genPassphraseCmd())

	return cmd
}

func genPasswordCmd() *cobra.Command {
	var length int
	var noSymbols bool

	cmd := &cobra.Command{
		Use:   "password",
		Short: "Generate a random character password",
		RunE: func(_ *cobra.Command, _ []string) error {
			charset := lowerLetters + upperLetters + digits
			if !noSymbols {
				charset += symbols
			}

			password := make([]byte, length)
			for i := 0; i < length; i++ {
				num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
				if err != nil {
					return fmt.Errorf("entropy failure: %w", err)
				}
				password[i] = charset[num.Int64()]
			}

			if JSONOutput {
				printJSON(map[string]string{"password": string(password)})
			} else {
				SecurePrint(string(password))
			}

			// Memory Hygiene: Zero out the password bytes immediately after use
			for i := range password {
				password[i] = 0
			}

			return nil
		},
	}

	cmd.Flags().IntVarP(&length, "length", "l", 32, "Length of the generated password")
	cmd.Flags().BoolVarP(&noSymbols, "no-symbols", "n", false, "Exclude symbols from the password")
	return cmd
}

func genPassphraseCmd() *cobra.Command {
	var words int
	var separator string

	cmd := &cobra.Command{
		Use:   "passphrase",
		Short: "Generate a mnemonic passphrase",
		RunE: func(_ *cobra.Command, _ []string) error {
			result, err := crypto.GeneratePassphrase(words, separator)
			if err != nil {
				return err
			}

			if JSONOutput {
				printJSON(map[string]string{"passphrase": result})
			} else {
				SecurePrint(result)
			}
			return nil
		},
	}

	cmd.Flags().IntVarP(&words, "words", "w", 4, "Number of words for the passphrase")
	cmd.Flags().StringVarP(&separator, "separator", "p", "-", "Separator between words")
	return cmd
}
