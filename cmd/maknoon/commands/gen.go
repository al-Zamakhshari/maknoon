package commands

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/spf13/cobra"
	"github.com/a-khallaf/maknoon/pkg/crypto"
)

const (
	lowerLetters = "abcdefghijklmnopqrstuvwxyz"
	upperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits       = "0123456789"
	symbols      = "!@#$%^&*()-_=+[]{}|;:,.<>?"
)

func GenCmd() *cobra.Command {
	var length int
	var noSymbols bool
	var words int
	var separator string

	cmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate a high-entropy secure password or passphrase",
		RunE: func(cmd *cobra.Command, args []string) error {
			if words > 0 {
				// Passphrase Mode
				var passphrase []string
				for i := 0; i < words; i++ {
					num, err := rand.Int(rand.Reader, big.NewInt(int64(len(crypto.WordList))))
					if err != nil {
						return fmt.Errorf("entropy failure: %w", err)
					}
					passphrase = append(passphrase, crypto.WordList[num.Int64()])
				}

				result := ""
				for i, word := range passphrase {
					result += word
					if i < len(passphrase)-1 {
						result += separator
					}
				}
				fmt.Println(result)
				
				// Clear the slice from memory
				for i := range passphrase {
					passphrase[i] = ""
				}
				passphrase = nil
				return nil
			}

			// Random String Mode
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

			fmt.Println(string(password))

			// Memory Hygiene: Zero out the password bytes immediately after printing
			defer func() {
				for i := range password {
					password[i] = 0
				}
			}()

			return nil
		},
	}

	cmd.Flags().IntVarP(&length, "length", "l", 32, "Length of the generated password (random string mode)")
	cmd.Flags().BoolVarP(&noSymbols, "no-symbols", "n", false, "Exclude symbols from the password (random string mode)")
	cmd.Flags().IntVarP(&words, "words", "w", 0, "Number of words for a passphrase (e.g. 4 for 'detect-logic-future-ocean')")
	cmd.Flags().StringVarP(&separator, "separator", "p", "-", "Separator between words in a passphrase")
	
	return cmd
}
