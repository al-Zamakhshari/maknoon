package commands

import (
	"fmt"
	"os"

	"github.com/a-khallaf/maknoon/pkg/crypto"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// EncryptCmd returns the cobra command for encrypting files and directories.
func EncryptCmd() *cobra.Command {
	var output string
	var pubKeyPath string
	var passphrase string
	var compress bool
	var concurrency int

	cmd := &cobra.Command{
		Use:   "encrypt [file/dir]",
		Short: "Encrypt a file or directory symmetrically or asymmetrically",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inputPath := args[0]

			stat, err := os.Stat(inputPath)
			if err != nil {
				return fmt.Errorf("failed to access input path: %w", err)
			}

			outPath := output
			if outPath == "" {
				outPath = inputPath + ".makn"
			}
			out, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}
			defer out.Close()

			opts := crypto.Options{
				Compress:    compress,
				IsArchive:   stat.IsDir(),
				Concurrency: concurrency,
			}

			// Resolve Public Key if provided
			if pubKeyPath != "" {
				resolvedPath := crypto.ResolveKeyPath(pubKeyPath)
				pk, err := os.ReadFile(resolvedPath)
				if err != nil {
					return err
				}
				opts.PublicKey = pk
			} else {
				// Handle Passphrase
				if passphrase != "" {
					opts.Passphrase = []byte(passphrase)
				} else if env := os.Getenv("MAKNOON_PASSPHRASE"); env != "" {
					opts.Passphrase = []byte(env)
				} else {
					fmt.Print("Enter passphrase: ")
					p, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil {
						return err
					}
					opts.Passphrase = p

					fmt.Print("Confirm passphrase: ")
					confirm, _ := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if string(opts.Passphrase) != string(confirm) {
						return fmt.Errorf("passphrases do not match")
					}
				}
			}

			// Clean RAM on exit
			defer func() {
				if len(opts.Passphrase) > 0 {
					crypto.SafeClear(opts.Passphrase)
				}
			}()

			fmt.Printf("Protecting '%s'...\n", inputPath)

			// Progress wrapping (tracking the INPUT size is always accurate)
			totalSize := stat.Size()
			if stat.IsDir() {
				totalSize = -1
			}
			bar := progressbar.DefaultBytes(totalSize, "preserving")
			opts.ProgressReader = bar

			return crypto.Protect(inputPath, out, opts)
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	cmd.Flags().StringVarP(&pubKeyPath, "public-key", "p", "", "Path to the recipient's public key")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase for symmetric encryption")
	cmd.Flags().BoolVarP(&compress, "compress", "c", false, "Enable Zstd compression")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "j", 0, "Number of parallel workers (0 for auto)")
	return cmd
}
