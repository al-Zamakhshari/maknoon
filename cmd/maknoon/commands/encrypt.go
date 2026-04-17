package commands

import (
	"encoding/json"
	"fmt"
	"io"
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
	var quiet bool
	var profile int
	var profileFile string

	cmd := &cobra.Command{
		Use:   "encrypt [file/dir]",
		Short: "Encrypt a file or directory symmetrically or asymmetrically",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inputPath := args[0]
			var input io.Reader
			var inputName string
			var totalSize int64 = -1
			isDir := false

			if inputPath == "-" {
				input = os.Stdin
				inputName = "stdin"
			} else {
				stat, err := os.Stat(inputPath)
				if err != nil {
					return fmt.Errorf("failed to access input path: %w", err)
				}
				isDir = stat.IsDir()
				if isDir {
					totalSize = 0 // progressbar doesn't like -1 with DefaultBytes
				} else {
					totalSize = stat.Size()
				}
				inputName = inputPath
				// Protect will open the file if input is nil
			}

			outPath := output
			var out io.Writer
			if outPath == "-" {
				out = os.Stdout
				quiet = true // Force quiet mode if writing to stdout
			} else {
				if outPath == "" {
					if inputPath == "-" {
						return fmt.Errorf("output path required when reading from stdin (use -o)")
					}
					outPath = inputPath + ".makn"
				}
				f, err := os.Create(outPath)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer func() { _ = f.Close() }()
				out = f
			}

			if profileFile != "" {
				raw, err := os.ReadFile(profileFile)
				if err != nil {
					return fmt.Errorf("failed to read profile file: %w", err)
				}
				var dp crypto.DynamicProfile
				if err := json.Unmarshal(raw, &dp); err != nil {
					return fmt.Errorf("invalid profile format: %w", err)
				}
				if err := dp.Validate(); err != nil {
					return fmt.Errorf("invalid profile parameters: %w", err)
				}
				crypto.RegisterProfile(&dp)
				profile = int(dp.ID())
			}

			opts := crypto.Options{
				Compress:    compress,
				IsArchive:   isDir,
				Concurrency: concurrency,
				ProfileID:   byte(profile),
			}

			// Resolve Public Key if provided or in env
			resolvedPath := crypto.ResolveKeyPath(pubKeyPath, "MAKNOON_PUBLIC_KEY")
			if resolvedPath != "" {
				pk, err := os.ReadFile(resolvedPath)
				if err != nil && pubKeyPath != "" {
					return err
				}
				if err == nil {
					opts.PublicKey = pk
				}
			}

			if len(opts.PublicKey) == 0 {
				// Handle Passphrase
				if passphrase != "" {
					opts.Passphrase = []byte(passphrase)
				} else if env := os.Getenv("MAKNOON_PASSPHRASE"); env != "" {
					opts.Passphrase = []byte(env)
				} else {
					if inputPath == "-" {
						return fmt.Errorf("passphrase required via MAKNOON_PASSPHRASE or -s when reading from stdin")
					}
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

			if !quiet && totalSize > 0 {
				fmt.Printf("Protecting '%s'...\n", inputName)
				bar := progressbar.DefaultBytes(totalSize, "preserving")
				opts.ProgressReader = bar
			} else if !quiet {
				fmt.Printf("Protecting '%s'...\n", inputName)
			}

			return crypto.Protect(inputName, input, out, opts)
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (use - for stdout)")
	cmd.Flags().StringVarP(&pubKeyPath, "public-key", "p", "", "Path to the recipient's public key")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase for symmetric encryption")
	cmd.Flags().BoolVarP(&compress, "compress", "c", false, "Enable Zstd compression")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "j", 0, "Number of parallel workers (0 for auto)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress bars and informational messages")
	cmd.Flags().IntVar(&profile, "profile", 0, "Cryptographic profile ID (1: NIST PQC, 2: AES-GCM)")
	cmd.Flags().StringVar(&profileFile, "profile-file", "", "Path to a custom profile JSON file")
	return cmd
}
