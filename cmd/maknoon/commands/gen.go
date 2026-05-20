package commands

import (
	"fmt"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// GenCmd returns the cobra command for generating secure passwords / passphrases.
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
	var (
		length       int
		noSymbols    bool
		storeVault   string
		storeUser    string
		storeOver    bool
		vaultPass    string
		minEntropy   int
		storeService string
	)

	cmd := &cobra.Command{
		Use:   "password",
		Short: "Generate a random character password",
		RunE: func(_ *cobra.Command, _ []string) error {
			// Entropy check before generation
			charsetSize := crypto.PasswordCharsetSize(noSymbols)
			bits := crypto.PasswordEntropy(length, charsetSize)
			if minEntropy > 0 && bits < float64(minEntropy) {
				return fmt.Errorf(
					"generated entropy %.1f bits is below minimum %d bits — increase --length",
					bits, minEntropy,
				)
			}

			generated, err := GlobalContext.Engine.GeneratePassword(nil, length, noSymbols)
			if err != nil {
				return err
			}

			if storeService != "" {
				if err := storeInVault(storeService, storeVault, storeUser, vaultPass, generated, storeOver); err != nil {
					return err
				}
			}

			if JSONOutput {
				printJSON(crypto.GenResult{
					Password:      generated,
					EntropyBits:   bits,
					EntropyBitsPQ: bits / 2,
				})
			} else {
				SecurePrint(generated)
				fmt.Fprintf(os.Stderr, "[%.1f bits entropy · %.1f bits post-quantum (Grover)]\n",
					bits, bits/2)
				if storeService != "" {
					fmt.Fprintf(os.Stderr, "Stored in vault '%s' under service '%s'\n",
						storeVault, storeService)
				}
			}

			return nil
		},
	}

	cmd.Flags().IntVarP(&length, "length", "l", 32, "Length of the generated password")
	cmd.Flags().BoolVarP(&noSymbols, "no-symbols", "n", false, "Exclude symbols from the password")
	cmd.Flags().StringVar(&storeService, "store", "", "Store in vault under this service name")
	cmd.Flags().StringVarP(&storeVault, "vault", "v", "default", "Vault name to store into")
	cmd.Flags().StringVar(&storeUser, "username", "", "Username field for vault entry")
	cmd.Flags().BoolVar(&storeOver, "overwrite", false, "Overwrite existing vault entry")
	cmd.Flags().StringVarP(&vaultPass, "passphrase", "s", "", "Master passphrase for vault storage")
	cmd.Flags().IntVar(&minEntropy, "min-entropy", 0, "Minimum required entropy in bits (0 = no check)")
	return cmd
}

func genPassphraseCmd() *cobra.Command {
	var (
		words        int
		separator    string
		storeVault   string
		storeUser    string
		storeOver    bool
		vaultPass    string
		minEntropy   int
		storeService string
	)

	cmd := &cobra.Command{
		Use:   "passphrase",
		Short: "Generate a mnemonic passphrase",
		RunE: func(_ *cobra.Command, _ []string) error {
			// Entropy check before generation
			bits := crypto.PassphraseEntropy(words, len(crypto.PassphraseWordList))
			if minEntropy > 0 && bits < float64(minEntropy) {
				return fmt.Errorf(
					"generated entropy %.1f bits is below minimum %d bits — increase --words",
					bits, minEntropy,
				)
			}

			result, err := GlobalContext.Engine.GeneratePassphrase(nil, words, separator)
			if err != nil {
				return err
			}

			if storeService != "" {
				if err := storeInVault(storeService, storeVault, storeUser, vaultPass, result, storeOver); err != nil {
					return err
				}
			}

			if JSONOutput {
				printJSON(crypto.GenResult{
					Passphrase:    result,
					EntropyBits:   bits,
					EntropyBitsPQ: bits / 2,
				})
			} else {
				SecurePrint(result)
				fmt.Fprintf(os.Stderr, "[%.1f bits entropy · %.1f bits post-quantum (Grover)]\n",
					bits, bits/2)
				if storeService != "" {
					fmt.Fprintf(os.Stderr, "Stored in vault '%s' under service '%s'\n",
						storeVault, storeService)
				}
			}

			return nil
		},
	}

	cmd.Flags().IntVarP(&words, "words", "w", 6, "Number of words for the passphrase")
	cmd.Flags().StringVarP(&separator, "separator", "p", "-", "Separator between words")
	cmd.Flags().StringVar(&storeService, "store", "", "Store in vault under this service name")
	cmd.Flags().StringVarP(&storeVault, "vault", "v", "default", "Vault name to store into")
	cmd.Flags().StringVar(&storeUser, "username", "", "Username field for vault entry")
	cmd.Flags().BoolVar(&storeOver, "overwrite", false, "Overwrite existing vault entry")
	cmd.Flags().StringVarP(&vaultPass, "passphrase", "s", "", "Master passphrase for vault storage")
	cmd.Flags().IntVar(&minEntropy, "min-entropy", 0, "Minimum required entropy in bits (0 = no check)")
	return cmd
}

// storeInVault persists a generated secret into the named vault entry.
func storeInVault(service, vaultName, username, vaultPass, secret string, overwrite bool) error {
	path, err := resolveVaultPath(vaultName)
	if err != nil {
		return err
	}

	var vPass []byte
	if vaultPass != "" {
		vPass = []byte(vaultPass)
	} else {
		vPass, _, err = getPassphrase("Enter Vault Master Passphrase: ")
		if err != nil {
			return err
		}
	}
	defer crypto.SafeClear(vPass)

	entry := &crypto.VaultEntry{
		Service:  service,
		Username: username,
		Password: crypto.SecretBytes(secret),
	}
	return GlobalContext.Engine.VaultSet(nil, path, entry, vPass, "", overwrite)
}
