package commands

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	var sessionKeyHex string
	var compress bool
	var concurrency int
	var quiet bool
	var verbose bool
	var stealth bool
	var profileStr string
	var profileFile string
	var tofu bool
	var shred bool
	var recursive bool
	var dryRun bool
	var threshold int

	// KDF overrides
	var argonTime uint32
	var argonMem uint32
	var argonThrd uint8

	cmd := &cobra.Command{
		Use:   "encrypt <file|dir> [file2 ...]",
		Short: "Encrypt one or more files or a directory",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()

			// Multiple explicit files — derive session key once, encrypt each.
			if len(args) > 1 {
				opts := crypto.Options{}
				if cmd.Flags().Changed("compress") {
					opts.Compress = crypto.BoolPtr(compress)
				}
				if cmd.Flags().Changed("stealth") {
					opts.Stealth = crypto.BoolPtr(stealth)
				}
				if sessionKeyHex != "" {
					key, err := decodeHexKey(sessionKeyHex)
					if err != nil {
						return fmt.Errorf("--session-key: %w", err)
					}
					opts.SessionKey = key
				}
				if err := resolveEncryptionKeysMulti(&opts, pubKeyPaths, passphrase, args[0], tofu); err != nil {
					p.RenderError(err)
					return err
				}
				defer func() {
					crypto.SafeClear(opts.Passphrase)
					crypto.SafeClear(opts.SigningKey)
				}()

				res, err := GlobalContext.Engine.ProtectFiles(nil, args, output, opts)
				if err != nil {
					p.RenderError(err)
					return err
				}
				if !quiet {
					kdfNote := ""
					if res.SessionKeyDerived {
						kdfNote = " (session key auto-derived — KDF ran once)"
					}
					fmt.Fprintf(os.Stderr, "%s %d/%d file(s) encrypted%s\n",
						icon("✓", "ok"), res.TotalFiles, len(args), kdfNote)
					for _, e := range res.Errors {
						fmt.Fprintf(os.Stderr, "  %s %s: %s\n", icon("✗", "FAIL"), e.Path, e.Err)
					}
				}
				p.RenderSuccess(res)
				if len(res.Errors) > 0 {
					return fmt.Errorf("%d file(s) failed to encrypt", len(res.Errors))
				}
				return nil
			}

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

			// --dry-run for single file or non-recursive.
			if dryRun && !recursive {
				outPath := inputPath + ".makn"
				if output != "" {
					outPath = output
				}
				fmt.Fprintf(os.Stderr, "[dry-run] would encrypt: %s → %s\n", inputPath, outPath)
				fmt.Fprintln(os.Stderr, "[dry-run] No files written.")
				return nil
			}

			// --recursive: encrypt each file in the directory individually,
			// auto-deriving one session key for the run (one Argon2id call total).
			if recursive && isDir {
				// --dry-run: walk and preview without encrypting.
				if dryRun {
					return dryRunEncryptDir(inputPath, output)
				}
				opts := crypto.Options{}
				if cmd.Flags().Changed("compress") {
					opts.Compress = crypto.BoolPtr(compress)
				}
				if cmd.Flags().Changed("stealth") {
					opts.Stealth = crypto.BoolPtr(stealth)
				}
				if err := resolveEncryptionKeysMulti(&opts, pubKeyPaths, passphrase, inputPath, tofu); err != nil {
					p.RenderError(err)
					return err
				}
				defer func() {
					crypto.SafeClear(opts.Passphrase)
					crypto.SafeClear(opts.SigningKey)
				}()

				res, err := GlobalContext.Engine.ProtectDirectory(nil, inputPath, output, opts)
				if err != nil {
					p.RenderError(err)
					return err
				}

				if !quiet {
					kdfNote := ""
					if res.SessionKeyDerived {
						kdfNote = " (session key auto-derived — KDF ran once)"
					}
					fmt.Fprintf(os.Stderr, "%s %d file(s) encrypted%s\n", icon("✓", "ok"), res.TotalFiles, kdfNote)
					for _, e := range res.Errors {
						fmt.Fprintf(os.Stderr, "  %s %s: %s\n", icon("✗", "FAIL"), e.Path, e.Err)
					}
				}
				p.RenderSuccess(res)
				if len(res.Errors) > 0 {
					return fmt.Errorf("%d file(s) failed to encrypt", len(res.Errors))
				}
				return nil
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

			if sessionKeyHex != "" {
				key, err := decodeHexKey(sessionKeyHex)
				if err != nil {
					return fmt.Errorf("--session-key: %w", err)
				}
				opts.SessionKey = key
			}

			if err := resolveEncryptionKeysMulti(&opts, pubKeyPaths, passphrase, inputPath, tofu); err != nil {
				p.RenderError(err)
				return err
			}

			if signKeyPath != "" || viper.GetString("private_key") != "" {
				sk, err := LoadPrivateKey(signKeyPath, "MAKNOON_PRIVATE_KEY", []byte(passphrase))
				if err == nil {
					opts.SigningKey = sk
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

			// Threshold encryption: K-of-N, requires --threshold K with -p for N recipients.
			if threshold >= 2 && len(opts.Recipients) >= threshold {
				close(events)
				// Open the input file — resolveEncryptInput closed it after stat.
				inFile, err := os.Open(inputPath)
				if err != nil {
					p.RenderError(err)
					return err
				}
				defer inFile.Close()

				flags := byte(0)
				if opts.Compress != nil && *opts.Compress {
					flags |= crypto.FlagCompress
				}
				var profileID byte
				if opts.ProfileID != nil {
					profileID = *opts.ProfileID
				}
				err = crypto.EncryptStreamThreshold(inFile, out, opts.Recipients, threshold, flags, 0, profileID, nil)
				if err != nil {
					p.RenderError(err)
					return err
				}
				if !quiet {
					fmt.Fprintf(os.Stderr, "%s Threshold encryption: %d-of-%d recipients required to decrypt\n",
						icon("✓", "ok"), threshold, len(opts.Recipients))
				}
				p.RenderSuccess(map[string]any{"status": "success", "threshold": threshold, "recipients": len(opts.Recipients)})
				return nil
			}

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
	cmd.Flags().StringVar(&sessionKeyHex, "session-key", "", "Pre-derived 64-char hex key (bypasses KDF — use 'maknoon session derive' to generate)")
	cmd.Flags().BoolVarP(&compress, "compress", "c", false, "Enable Zstd compression")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "j", 0, "Number of parallel workers (0 for auto); note: AES-NI hardware saturates at concurrency=1, so this flag only helps on non-AES-NI targets")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress bars and informational messages")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Enable internal pipeline tracing (slog)")
	cmd.Flags().BoolVar(&stealth, "stealth", false, "Enable fingerprint resistance (headerless)")
	cmd.Flags().BoolVar(&tofu, "trust-on-first-use", false, "Automatically add unknown signers to contacts")
	cmd.Flags().BoolVar(&shred, "shred", false, "Securely delete original file after successful encryption")
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Encrypt each file in a directory individually (derives session key once — one KDF cost for the whole run)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview what would be encrypted without writing any files")
	cmd.Flags().IntVar(&threshold, "threshold", 0, "K-of-N threshold decryption: require K out of N recipients to decrypt (must be ≥ 2)")
	cmd.Flags().StringVar(&profileStr, "profile", "", "Cryptographic profile (nist, conservative)")
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

// dryRunEncryptDir walks a directory and prints what would be encrypted.
func dryRunEncryptDir(inputDir, outputDir string) error {
	count, skipped := 0, 0
	err := filepath.WalkDir(inputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasSuffix(path, ".makn") {
			skipped++
			return nil
		}
		var outPath string
		if outputDir != "" {
			rel, _ := filepath.Rel(inputDir, path)
			outPath = filepath.Join(outputDir, rel+".makn")
		} else {
			outPath = path + ".makn"
		}
		fmt.Fprintf(os.Stderr, "[dry-run] would encrypt: %s → %s\n", path, outPath)
		count++
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[dry-run] %d file(s), %d skipped (already .makn). No files written.\n", count, skipped)
	return nil
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
	// Session key already set — no passphrase or recipient resolution needed.
	if len(opts.SessionKey) > 0 {
		return nil
	}

	if len(pubKeyPaths) == 0 {
		if env := viper.GetString("public_key"); env != "" {
			pubKeyPaths = append(pubKeyPaths, env)
		}
	}

	for _, path := range pubKeyPaths {
		record, err := GlobalContext.Engine.ResolveIdentityInfo(nil, path, tofu)
		if err != nil {
			return err
		}
		opts.Recipients = append(opts.Recipients, record.KEMPubKey)

		// Show fingerprint for registry-resolved handles (@alice@corp.com).
		if strings.HasPrefix(path, "@") && len(record.SIGPubKey) > 0 {
			fingerprint, ferr := crypto.DerivePeerID(record.SIGPubKey)
			if ferr == nil {
				fmt.Fprintf(os.Stderr, "%s encrypting to %s (%s)\n",
					icon("»", ">>"), fingerprint, path)
			}
			// Warn if the key is close to expiry.
			if !record.ExpiresAt.IsZero() {
				remaining := time.Until(record.ExpiresAt)
				if remaining < 0 {
					return fmt.Errorf("key for %s has expired — ask them to republish their identity", path)
				} else if remaining < 48*time.Hour {
					fmt.Fprintf(os.Stderr, "%s key for %s expires in %s — ask them to republish\n",
						icon("⚠️ ", "WARNING:"), path, remaining.Round(time.Minute))
				}
			}
		}
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
