package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
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
			input, inputName, totalSize, isDir, err := resolveEncryptInput(inputPath)
			if err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}
			if input != nil {
				if f, ok := input.(*os.File); ok {
					defer func() { _ = f.Close() }()
				}
			}

			out, outPath, err := resolveEncryptOutput(output, inputPath)
			if err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}
			if f, ok := out.(*os.File); ok {
				defer func() { _ = f.Close() }()
			}

			if profileFile != "" {
				if err := loadCustomProfile(profileFile, &profile); err != nil {
					if JSONOutput {
						printErrorJSON(err)
						return nil
					}
					return err
				}
			}

			opts := crypto.Options{
				Compress:    compress,
				IsArchive:   isDir,
				Concurrency: concurrency,
				ProfileID:   byte(profile),
			}

			if err := resolveEncryptionKeys(&opts, pubKeyPath, passphrase, inputPath); err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}

			// Clean RAM on exit
			defer func() {
				if len(opts.Passphrase) > 0 {
					crypto.SafeClear(opts.Passphrase)
				}
			}()

			if JSONOutput {
				quiet = true
			}

			if !quiet && totalSize > 0 {
				fmt.Printf("Protecting '%s'...\n", inputName)
				bar := progressbar.DefaultBytes(totalSize, "preserving")
				opts.ProgressReader = bar
			} else if !quiet {
				fmt.Printf("Protecting '%s'...\n", inputName)
			}

			if err := crypto.Protect(inputName, input, out, opts); err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}

			if JSONOutput {
				printJSON(map[string]string{"status": "success", "output": outPath})
			}

			return nil
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

func resolveEncryptInput(path string) (io.Reader, string, int64, bool, error) {
	if path == "-" {
		return os.Stdin, "stdin", -1, false, nil
	}
	stat, err := os.Stat(path)
	if err != nil {
		return nil, "", 0, false, err
	}
	isDir := stat.IsDir()
	var totalSize int64
	if isDir {
		totalSize = 0
	} else {
		totalSize = stat.Size()
	}
	return nil, path, totalSize, isDir, nil // Protect opens the file if nil
}

func resolveEncryptOutput(output, inputPath string) (io.Writer, string, error) {
	if output == "-" {
		return os.Stdout, "stdout", nil
	}
	outPath := output
	if outPath == "" {
		if inputPath == "-" {
			return nil, "", fmt.Errorf("output path required when reading from stdin (use -o)")
		}
		outPath = inputPath + ".makn"
	}
	f, err := os.Create(outPath)
	if err != nil {
		return nil, "", err
	}
	return f, outPath, nil
}

func loadCustomProfile(path string, profileID *int) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var dp crypto.DynamicProfile
	if err := json.Unmarshal(raw, &dp); err != nil {
		return err
	}
	if err := dp.Validate(); err != nil {
		return err
	}
	crypto.RegisterProfile(&dp)
	*profileID = int(dp.ID())
	return nil
}

func resolveEncryptionKeys(opts *crypto.Options, pubKeyPath, passphrase, inputPath string) error {
	resolvedPath := crypto.ResolveKeyPath(pubKeyPath, "MAKNOON_PUBLIC_KEY")
	if resolvedPath != "" {
		pk, err := os.ReadFile(resolvedPath)
		if err == nil {
			opts.PublicKey = pk
			return nil
		}
		if pubKeyPath != "" {
			return err
		}
	}

	if passphrase != "" {
		opts.Passphrase = []byte(passphrase)
		return nil
	}
	if env := os.Getenv("MAKNOON_PASSPHRASE"); env != "" {
		opts.Passphrase = []byte(env)
		return nil
	}

	if inputPath == "-" || JSONOutput {
		return fmt.Errorf("passphrase required via MAKNOON_PASSPHRASE or -s")
	}

	fmt.Print("Enter passphrase: ")
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}

	fmt.Print("Confirm passphrase: ")
	confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		crypto.SafeClear(p)
		return err
	}
	defer crypto.SafeClear(confirm)

	if string(p) != string(confirm) {
		crypto.SafeClear(p)
		return fmt.Errorf("passphrases do not match")
	}
	opts.Passphrase = p
	return nil
}
