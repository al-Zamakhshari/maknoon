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
	var pubKeyPaths []string
	var signKeyPath string
	var passphrase string
	var compress bool
	var concurrency int
	var quiet bool
	var verbose bool
	var stealth bool
	var profile int
	var profileFile string

	// KDF overrides
	var argonTime uint32
	var argonMem uint32
	var argonThrd uint8

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
				Verbose:     verbose,
				Stealth:     stealth,
			}

			// Apply KDF overrides to the profile if it's ProfileV1
			// REFACTOR: This currently only works for symmetric encryption using the default profile.
			// For a production-grade tool, these would be packed into the header.
			// For now, we'll focus on the architecture.

			if err := resolveEncryptionKeysMulti(&opts, pubKeyPaths, passphrase, inputPath); err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}

			if signKeyPath != "" || os.Getenv("MAKNOON_PRIVATE_KEY") != "" {
				resolvedSignPath := crypto.ResolveKeyPath(signKeyPath, "MAKNOON_PRIVATE_KEY")
				if resolvedSignPath != "" {
					sk, err := os.ReadFile(resolvedSignPath)
					if err == nil {
						opts.SigningKey = sk
					}
				}
			}

			defer func() {
				if len(opts.Passphrase) > 0 {
					crypto.SafeClear(opts.Passphrase)
				}
				if len(opts.SigningKey) > 0 {
					crypto.SafeClear(opts.SigningKey)
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
	cmd.Flags().StringSliceVarP(&pubKeyPaths, "public-key", "p", []string{}, "Path to recipient public key(s)")
	cmd.Flags().StringVar(&signKeyPath, "sign-key", "", "Path to your private ML-DSA key for integrated signing")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase for symmetric encryption")
	cmd.Flags().BoolVarP(&compress, "compress", "c", false, "Enable Zstd compression")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "j", 0, "Number of parallel workers (0 for auto)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress bars and informational messages")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Enable internal pipeline tracing (slog)")
	cmd.Flags().BoolVar(&stealth, "stealth", false, "Enable fingerprint resistance (headerless)")
	cmd.Flags().IntVar(&profile, "profile", 0, "Cryptographic profile ID (1: NIST PQC, 2: AES-GCM)")
	cmd.Flags().StringVar(&profileFile, "profile-file", "", "Path to a custom profile JSON file")

	// KDF Flags
	cmd.Flags().Uint32Var(&argonTime, "argon-time", 3, "Argon2id iterations")
	cmd.Flags().Uint32Var(&argonMem, "argon-mem", 64*1024, "Argon2id memory in KB")
	cmd.Flags().Uint8Var(&argonThrd, "argon-threads", 4, "Argon2id parallel threads")

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
	return nil, path, totalSize, isDir, nil
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
	if profileID != nil {
		*profileID = int(dp.ID())
	}
	return nil
}

func resolveEncryptionKeysMulti(opts *crypto.Options, pubKeyPaths []string, passphrase, inputPath string) error {
	if len(pubKeyPaths) == 0 {
		if env := os.Getenv("MAKNOON_PUBLIC_KEY"); env != "" {
			pubKeyPaths = append(pubKeyPaths, env)
		}
	}

	for _, path := range pubKeyPaths {
		resolvedPath := crypto.ResolveKeyPath(path, "")
		if resolvedPath == "" {
			return fmt.Errorf("public key not found: %s", path)
		}
		pk, err := os.ReadFile(resolvedPath)
		if err != nil {
			return fmt.Errorf("failed to read public key %s: %w", path, err)
		}
		opts.PublicKeys = append(opts.PublicKeys, pk)
	}

	if len(opts.PublicKeys) > 0 {
		return nil
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
