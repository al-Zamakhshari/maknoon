package commands

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

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
	var profileStr string
	var profileFile string
	var tofu bool
	var shred bool

	// KDF overrides
	var argonTime uint32
	var argonMem uint32
	var argonThrd uint8

	cmd := &cobra.Command{
		Use:   "encrypt [file/dir]",
		Short: "Encrypt a file or directory symmetrically or asymmetrically",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			inputPath := args[0]
			input, _, _, isDir, err := resolveEncryptInput(inputPath)
			if err != nil {
				p.RenderError(err)
				return err
			}
			if input != nil {
				if f, ok := input.(*os.File); ok && f != os.Stdin {
					_ = f.Close()
				}
			}

			out, _, err := resolveEncryptOutput(output, inputPath)
			if err != nil {
				p.RenderError(err)
				return err
			}
			if f, ok := out.(*os.File); ok {
				defer func() { _ = f.Close() }()
			}

			if profileFile != "" {
				dp, err := GlobalContext.Engine.LoadCustomProfile(nil, profileFile)
				if err != nil {
					p.RenderError(err)
					return err
				}
				profileStr = fmt.Sprintf("%d", dp.ID())
			}

			profileID := byte(0)
			if profileStr != "" {
				var err error
				profileID, err = resolveProfile(profileStr)
				if err != nil {
					p.RenderError(err)
					return err
				}
			}

			opts := crypto.Options{
				IsArchive: isDir,
				TotalSize: -1, // Resolved below
			}

			if cmd.Flags().Changed("compress") {
				opts.Compress = crypto.BoolPtr(compress)
			}
			if cmd.Flags().Changed("concurrency") {
				opts.Concurrency = crypto.IntPtr(concurrency)
			}
			if cmd.Flags().Changed("verbose") {
				opts.Verbose = crypto.BoolPtr(verbose)
			}
			if cmd.Flags().Changed("stealth") {
				opts.Stealth = crypto.BoolPtr(stealth)
			}
			if cmd.Flags().Changed("profile") || cmd.Flags().Changed("profile-file") {
				opts.ProfileID = crypto.BytePtr(profileID)
			}

			if err := resolveEncryptionKeysMulti(&opts, pubKeyPaths, passphrase, inputPath, tofu); err != nil {
				p.RenderError(err)
				return err
			}

			if signKeyPath != "" || viper.GetString("private_key") != "" {
				m := crypto.NewIdentityManager()
				resolvedSignPath := m.ResolveKeyPath(signKeyPath, "MAKNOON_PRIVATE_KEY")
				if resolvedSignPath != "" {
					var pin string
					if _, err := os.Stat(strings.TrimSuffix(resolvedSignPath, ".key") + ".fido2"); err == nil {
						var err2 error
						pin, err2 = getPIN()
						if err2 != nil {
							return err2
						}
					}
					sk, err := m.LoadPrivateKey(resolvedSignPath, []byte(passphrase), pin, false)
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

			if GlobalContext.UI.JSON {
				quiet = true
			}

			events := make(chan crypto.EngineEvent, 100)
			opts.EventStream = events
			done := make(chan struct{})
			go func() {
				handleEngineEvents(events, quiet)
				close(done)
			}()

			res, err := GlobalContext.Engine.Protect(nil, inputPath, nil, out, opts)
			close(events)
			<-done

			if err != nil {
				p.RenderError(err)
				return err
			}

			if shred && inputPath != "-" {
				if err := GlobalContext.Engine.SecureDelete(inputPath); err != nil {
					if !quiet {
						p.RenderMessage(fmt.Sprintf("Warning: failed to shred original file: %v", err))
					}
				}
			}

			p.RenderSuccess(res)
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
	cmd.Flags().BoolVar(&tofu, "trust-on-first-use", false, "Automatically add unknown signers to contacts")
	cmd.Flags().BoolVar(&shred, "shred", false, "Securely delete original file after successful encryption")
	cmd.Flags().StringVar(&profileStr, "profile", "", "Cryptographic profile (nist, aes, conservative)")
	cmd.Flags().StringVar(&profileFile, "profile-file", "", "Path to a custom profile JSON file")

	_ = cmd.RegisterFlagCompletionFunc("public-key", completeIdentities)
	_ = cmd.RegisterFlagCompletionFunc("sign-key", completeIdentities)
	_ = cmd.RegisterFlagCompletionFunc("profile", completeProfiles)

	// KDF overrides
	cmd.Flags().Uint32Var(&argonTime, "argon-time", 0, "Argon2id iterations")
	cmd.Flags().Uint32Var(&argonMem, "argon-mem", 0, "Argon2id memory in KB")
	cmd.Flags().Uint8Var(&argonThrd, "argon-threads", 0, "Argon2id parallel threads")

	return cmd
}

func resolveEncryptInput(path string) (io.Reader, string, int64, bool, error) {
	if path == "-" {
		return os.Stdin, "stdin", -1, false, nil
	}

	if err := validatePath(path); err != nil {
		return nil, "", 0, false, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, "", 0, false, err
	}

	if info.IsDir() {
		return nil, filepath.Base(path), -1, true, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, "", 0, false, err
	}
	return f, info.Name(), info.Size(), false, nil
}

func resolveEncryptOutput(outPath, inPath string) (io.Writer, string, error) {
	if outPath == "-" {
		return os.Stdout, "stdout", nil
	}

	if outPath == "" {
		if inPath == "-" {
			return nil, "", fmt.Errorf("output path required when reading from stdin")
		}
		outPath = inPath + ".makn"
	}

	if err := validatePath(outPath); err != nil {
		return nil, "", err
	}

	f, err := os.Create(outPath)
	if err != nil {
		return nil, "", err
	}
	return f, outPath, nil
}

func resolveEncryptionKeysMulti(opts *crypto.Options, pubKeyPaths []string, passphrase, inputPath string, tofu bool) error {
	m := crypto.NewIdentityManager()
	if len(pubKeyPaths) == 0 {
		if env := viper.GetString("public_key"); env != "" {
			pubKeyPaths = append(pubKeyPaths, env)
		}
	}

	for _, path := range pubKeyPaths {
		pk, err := m.ResolvePublicKey(path, tofu)
		if err != nil {
			return err
		}
		opts.Recipients = append(opts.Recipients, pk)
	}

	if len(opts.Recipients) > 0 {
		return nil
	}

	if passphrase != "" {
		opts.Passphrase = []byte(passphrase)
		return nil
	}

	var err error
	var interactive bool
	opts.Passphrase, interactive, err = getPassphrase("Enter passphrase: ")
	if err != nil {
		return err
	}

	if interactive {
		fmt.Print("Confirm passphrase: ")
		confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			crypto.SafeClear(opts.Passphrase)
			return err
		}
		defer crypto.SafeClear(confirm)

		if string(opts.Passphrase) != string(confirm) {
			crypto.SafeClear(opts.Passphrase)
			return fmt.Errorf("passphrases do not match")
		}
	}
	return nil
}
