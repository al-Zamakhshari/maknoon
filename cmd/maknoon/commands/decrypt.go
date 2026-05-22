package commands

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DecryptCmd returns the cobra command for decrypting .makn files.
func DecryptCmd() *cobra.Command {
	var output string
	var keyPath string
	var senderKeyPath string
	var passphrase string
	var sessionKeyHex string
	var concurrency int
	var quiet bool
	var verbose bool
	var profileFile string
	var overwrite bool
	var stealth bool
	var tofu bool
	var recursive bool
	var dryRun bool
	var collectShare bool
	var combineShares string

	cmd := &cobra.Command{
		Use:   "decrypt <file.makn> [file2.makn ...]",
		Short: "Decrypt one or more .makn files",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()

			// --collect-share: unwrap this recipient's Shamir share from a threshold file.
			if collectShare && len(args) == 1 {
				in, _, _, err := resolveDecryptInput(args[0])
				if err != nil {
					p.RenderError(err)
					return err
				}
				privBytes, err := LoadPrivateKey(keyPath, "MAKNOON_PRIVATE_KEY", []byte(passphrase))
				if err != nil {
					p.RenderError(err)
					return err
				}
				defer crypto.SafeClear(privBytes)

				share, err := crypto.DecryptThresholdCollectShare(in, privBytes, 0)
				if err != nil {
					p.RenderError(err)
					return err
				}
				shareJSON, _ := crypto.ThresholdShareToJSON(share)

				outDest := output
				if outDest == "" {
					outDest = args[0] + ".share"
				}
				if outDest == "-" {
					fmt.Println(string(shareJSON))
				} else {
					if err := os.WriteFile(outDest, shareJSON, 0600); err != nil {
						p.RenderError(err)
						return err
					}
					if !quiet {
						fmt.Fprintf(os.Stderr, "%s Share %d/%d saved to %s\n",
							icon("✓", "ok"), share.Index, share.Total, outDest)
					}
				}
				p.RenderSuccess(map[string]any{"status": "success", "share_index": share.Index, "threshold": share.Threshold})
				return nil
			}

			// --combine: load K share files and decrypt.
			if combineShares != "" && len(args) == 1 {
				sharePaths := strings.Split(combineShares, ",")
				var shares []*crypto.ThresholdShare
				for _, sp := range sharePaths {
					data, err := os.ReadFile(strings.TrimSpace(sp))
					if err != nil {
						return fmt.Errorf("reading share %s: %w", sp, err)
					}
					s, err := crypto.ThresholdShareFromJSON(data)
					if err != nil {
						return err
					}
					shares = append(shares, s)
				}

				in, _, _, err := resolveDecryptInput(args[0])
				if err != nil {
					p.RenderError(err)
					return err
				}

				if err := crypto.DecryptThresholdCombine(in, nil, output, shares, nil); err != nil {
					p.RenderError(err)
					return err
				}
				if !quiet {
					fmt.Fprintf(os.Stderr, "%s Threshold decryption successful (%d shares combined)\n",
						icon("✓", "ok"), len(shares))
				}
				return nil
			}

			// Multiple files — decrypt each individually.
			// Pass --session-key for O(1) cost; passphrase path pays KDF per file.
			if len(args) > 1 {
				opts := crypto.Options{}
				if sessionKeyHex != "" {
					key, err := decodeHexKey(sessionKeyHex)
					if err != nil {
						return fmt.Errorf("--session-key: %w", err)
					}
					opts.SessionKey = key
				} else if passphrase != "" {
					opts.Passphrase = []byte(passphrase)
					defer crypto.SafeClear(opts.Passphrase)
				} else {
					pass, _, err := getPassphrase("Enter passphrase: ")
					if err != nil {
						p.RenderError(err)
						return err
					}
					opts.Passphrase = pass
					defer crypto.SafeClear(opts.Passphrase)
				}
				if cmd.Flags().Changed("concurrency") {
					opts.Concurrency = crypto.IntPtr(concurrency)
				}

				res, err := GlobalContext.Engine.DecryptFiles(nil, args, output, opts)
				if err != nil {
					p.RenderError(err)
					return err
				}
				if !quiet {
					fmt.Fprintf(os.Stderr, "%s %d/%d file(s) decrypted\n",
						icon("✓", "ok"), res.TotalFiles, len(args))
					for _, e := range res.Errors {
						fmt.Fprintf(os.Stderr, "  %s %s: %s\n", icon("✗", "FAIL"), e.Path, e.Err)
					}
				}
				p.RenderSuccess(res)
				if len(res.Errors) > 0 {
					return fmt.Errorf("%d file(s) failed to decrypt", len(res.Errors))
				}
				return nil
			}

			inputFile := args[0]

			// --recursive: decrypt all *.makn files in a directory.
			if info, statErr := os.Stat(inputFile); statErr == nil && info.IsDir() && recursive {
				opts := crypto.Options{}
				if sessionKeyHex != "" {
					key, err := decodeHexKey(sessionKeyHex)
					if err != nil {
						return fmt.Errorf("--session-key: %w", err)
					}
					opts.SessionKey = key
				} else if passphrase != "" {
					opts.Passphrase = []byte(passphrase)
					defer crypto.SafeClear(opts.Passphrase)
				} else {
					pass, _, err := getPassphrase("Enter passphrase: ")
					if err != nil {
						p.RenderError(err)
						return err
					}
					opts.Passphrase = pass
					defer crypto.SafeClear(opts.Passphrase)
				}

				// --dry-run: walk and preview without decrypting.
				if dryRun {
					return dryRunDecryptDir(inputFile, output)
				}

				res, err := GlobalContext.Engine.DecryptDirectory(nil, inputFile, output, opts)
				if err != nil {
					p.RenderError(err)
					return err
				}
				if !quiet {
					fmt.Fprintf(os.Stderr, "%s %d file(s) decrypted\n", icon("✓", "ok"), res.TotalFiles)
					for _, e := range res.Errors {
						fmt.Fprintf(os.Stderr, "  %s %s: %s\n", icon("✗", "FAIL"), e.Path, e.Err)
					}
				}
				p.RenderSuccess(res)
				if len(res.Errors) > 0 {
					return fmt.Errorf("%d file(s) failed to decrypt", len(res.Errors))
				}
				return nil
			}

			// --dry-run for single file.
			if dryRun {
				outPath := strings.TrimSuffix(inputFile, ".makn")
				if output != "" {
					outPath = output
				}
				fmt.Fprintf(os.Stderr, "[dry-run] would decrypt: %s → %s\n", inputFile, outPath)
				fmt.Fprintln(os.Stderr, "[dry-run] No files written.")
				return nil
			}

			in, _, totalSize, err := resolveDecryptInput(inputFile)
			if err != nil {
				p.RenderError(err)
				return err
			}
			if f, ok := in.(*os.File); ok {
				defer func() { _ = f.Close() }()
			}

			if profileFile != "" {
				if _, err := GlobalContext.Engine.LoadCustomProfile(nil, profileFile); err != nil {
					p.RenderError(err)
					return err
				}
			}

			// 1. Peek at the header to determine encryption type and flags
			var magic string
			var flags byte
			var fullIn io.Reader

			if stealth {
				header := make([]byte, 2)
				if _, err := io.ReadFull(in, header); err != nil {
					err = fmt.Errorf("failed to read stealth header: %w", err)
					p.RenderError(err)
					return err
				}
				fullIn = io.MultiReader(bytes.NewReader(header), in)
				flags = header[1]

				// Infer magic based on provided decryption params
				if keyPath != "" || viper.GetString("private_key") != "" {
					magic = crypto.MagicHeaderAsym
				} else {
					magic = crypto.MagicHeader
				}
			} else {
				header := make([]byte, 6)
				if _, err := io.ReadFull(in, header); err != nil {
					err = fmt.Errorf("failed to read file header: %w", err)
					p.RenderError(err)
					return err
				}
				fullIn = io.MultiReader(bytes.NewReader(header), in)

				magic = string(header[:4])
				// V1: header layout is MAGIC(4) | ProfileID(1) | Flags(1)
				// V2: header layout is MAGIC(4) | FormatVersion(1) | ProfileID(1) | Flags(2 LE) ...
				// For V2, header[5] is ProfileID, not flags — real flags require reading 2 more bytes.
				// We skip the FlagSigned check for V2; the engine handles signature verification.
				isV2Magic := magic == crypto.MagicHeaderV2Sym || magic == crypto.MagicHeaderV2Asym
				if !isV2Magic {
					flags = header[5]
				}
			}

			// 2. Handle Passphrase/Identity logic
			password, finalKey, finalPriv, err := resolveDecryptionKey(magic, passphrase, keyPath, inputFile == "-")
			if err != nil {
				p.RenderError(err)
				return err
			}

			isV2 := magic == crypto.MagicHeaderV2Sym || magic == crypto.MagicHeaderV2Asym

			// 3. Resolve optional sender public key for integrated verification.
			// For V2 files, signature verification is handled inside the engine;
			// the CLI-level FlagSigned check only applies to V1 files.
			var senderKey []byte
			if !isV2 && flags&crypto.FlagSigned != 0 {
				resolvedSenderPath := GlobalContext.Engine.ResolveKeyPath(nil, senderKeyPath, "MAKNOON_PUBLIC_KEY")
				if resolvedSenderPath == "" {
					err := fmt.Errorf("file has integrated signature but sender public key not provided (use --sender-key)")
					p.RenderError(err)
					return err
				}
				sk, err := os.ReadFile(resolvedSenderPath)
				if err != nil {
					err = fmt.Errorf("failed to read sender public key: %w", err)
					p.RenderError(err)
					return err
				}
				senderKey = sk
			}

			// Clean RAM on exit
			defer func() {
				if len(password) > 0 {
					crypto.SafeClear(password)
				}
				if magic == crypto.MagicHeaderAsym {
					crypto.SafeClear(finalKey)
					crypto.SafeClear(finalPriv)
				}
			}()

			// 4. Prepare output path and check existence
			outPath, err := resolveDecryptionOutputPath(output, inputFile, flags)
			if err != nil {
				p.RenderError(err)
				return err
			}

			if outPath != "-" && !overwrite {
				if _, err := os.Stat(outPath); err == nil {
					err := fmt.Errorf("output path already exists: %s (use --overwrite to bypass)", outPath)
					p.RenderError(err)
					return err
				}
			}

			// 5. Initialize the Event Stream and Telemetry
			events := make(chan crypto.EngineEvent, 100)
			opts := crypto.Options{
				Passphrase:      finalKey,
				LocalPrivateKey: finalPriv,
				PublicKey:       senderKey,
				TotalSize:       totalSize,
				EventStream:     events,
			}
			if sessionKeyHex != "" {
				key, err := decodeHexKey(sessionKeyHex)
				if err != nil {
					return fmt.Errorf("--session-key: %w", err)
				}
				opts.SessionKey = key
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

			done := make(chan struct{})
			go func() {
				handleEngineEvents(events, quiet)
				close(done)
			}()

			if outPath == "-" {
				// If we are outputting to stdout, we MUST send JSON status to stderr
				// to avoid corrupting the raw data stream.
				oldWriter := GlobalContext.JSONWriter
				GlobalContext.JSONWriter = os.Stderr
				defer func() { GlobalContext.JSONWriter = oldWriter }()
			}

			res, err := GlobalContext.Engine.Unprotect(nil, fullIn, nil, outPath, opts)
			close(events)
			<-done

			if err != nil {
				p.RenderError(err)
				return err
			}

			// 6. Handle Trust Evidence and TOFU
			if senderKey != nil {
				gid := fmt.Sprintf("mk1_%x", crypto.Sha256Sum(senderKey)[:16])
				isTrusted := false
				var existingContact *crypto.Contact

				contacts, err := GlobalContext.Engine.ContactList(nil)
				if err == nil {
					for _, c := range contacts {
						if bytes.Equal(c.KEMPubKey, senderKey) || bytes.Equal(c.SIGPubKey, senderKey) {
							isTrusted = true
							existingContact = c
							break
						}
					}

					if !isTrusted && tofu {
						petname := "@" + gid[:12]
						err := GlobalContext.Engine.ContactAdd(nil, petname, "", hex.EncodeToString(senderKey), "Auto-learned via TOFU")
						if err == nil {
							isTrusted = true
							// Reload contacts to get the one we just added for existingContact
							newContacts, _ := GlobalContext.Engine.ContactList(nil)
							for _, c := range newContacts {
								if c.Petname == petname {
									existingContact = c
									break
								}
							}
						}
					}
				}

				if !GlobalContext.UI.JSON {
					status := "UNKNOWN (Untrusted)"
					if isTrusted {
						status = fmt.Sprintf("TRUSTED (%s)", existingContact.Petname)
					}
					p.RenderMessage(fmt.Sprintf("✔ Successfully verified signature from: %s [%s]", gid, status))
				} else {
					res.SignedBy = &crypto.TrustInfo{
						GID:       gid,
						IsTrusted: isTrusted,
					}
					if existingContact != nil {
						res.SignedBy.Petname = existingContact.Petname
					}
				}
			}

			p.RenderSuccess(res)
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path or directory (use - for stdout)")
	cmd.Flags().StringVarP(&keyPath, "private-key", "k", "", "Path to your private key")
	cmd.Flags().StringVar(&senderKeyPath, "sender-key", "", "Path to the sender's public key (required for signed files)")

	_ = cmd.RegisterFlagCompletionFunc("private-key", completeIdentities)
	_ = cmd.RegisterFlagCompletionFunc("sender-key", completeIdentities)

	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase for decryption")
	cmd.Flags().StringVar(&sessionKeyHex, "session-key", "", "Pre-derived 64-char hex key (bypasses KDF)")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "j", 0, "Number of parallel workers (0 for auto)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress bars and informational messages")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Enable internal pipeline tracing (slog)")
	cmd.Flags().BoolVar(&stealth, "stealth", false, "Enable fingerprint resistance (headerless)")
	cmd.Flags().BoolVar(&tofu, "trust-on-first-use", false, "Automatically add unknown signers to contacts")
	cmd.Flags().StringVar(&profileFile, "profile-file", "", "Path to a custom profile JSON file")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing files")
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Decrypt all .makn files in a directory (use --session-key for O(1) KDF cost)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview what would be decrypted without writing any files")
	cmd.Flags().BoolVar(&collectShare, "collect-share", false, "Threshold decrypt: unwrap your Shamir share and save it (use with -k and -o)")
	cmd.Flags().StringVar(&combineShares, "combine", "", "Threshold decrypt: combine K share files and decrypt (comma-separated paths)")
	return cmd
}

// dryRunDecryptDir walks a directory and prints what would be decrypted.
func dryRunDecryptDir(inputDir, outputDir string) error {
	count := 0
	err := filepath.WalkDir(inputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".makn") {
			return nil
		}
		var outPath string
		if outputDir != "" {
			rel, _ := filepath.Rel(inputDir, path)
			outPath = filepath.Join(outputDir, strings.TrimSuffix(rel, ".makn"))
		} else {
			outPath = strings.TrimSuffix(path, ".makn")
		}
		fmt.Fprintf(os.Stderr, "[dry-run] would decrypt: %s → %s\n", path, outPath)
		count++
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[dry-run] %d file(s) found. No files written.\n", count)
	return nil
}

func resolveDecryptInput(path string) (io.Reader, string, int64, error) {
	if path == "-" {
		return os.Stdin, "stdin", -1, nil
	}
	if err := validatePath(path); err != nil {
		return nil, "", 0, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to open input file: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, "", 0, err
	}
	return f, path, info.Size(), nil
}

func resolveDecryptionOutputPath(output, inputFile string, flags byte) (string, error) {
	outPath := ""
	if output == "-" {
		outPath = "-"
	} else if output != "" {
		outPath = output
	} else if inputFile == "-" {
		return "", fmt.Errorf("output path required when reading from stdin (use -o)")
	} else if flags&crypto.FlagArchive != 0 {
		outPath = "."
	} else if strings.HasSuffix(inputFile, ".makn") {
		outPath = strings.TrimSuffix(inputFile, ".makn")
	} else {
		outPath = inputFile + ".dec"
	}

	if err := validatePath(outPath); err != nil {
		return "", err
	}

	return outPath, nil
}

func resolveDecryptionKey(magic, manualPass, keyPath string, isStdin bool) ([]byte, []byte, []byte, error) {
	var password []byte
	if manualPass != "" {
		password = []byte(manualPass)
	} else if env := viper.GetString("passphrase"); env != "" {
		password = []byte(env)
	}

	if magic == crypto.MagicHeader {
		if len(password) == 0 {
			var err error
			password, _, err = getPassphrase("Enter passphrase: ")
			if err != nil {
				return nil, nil, nil, err
			}
		}
		return password, password, nil, nil
	}

	// V2 asymmetric (MAK3) — same key resolution as V1 asymmetric (MAKA).
	if magic == crypto.MagicHeaderAsym || magic == crypto.MagicHeaderV2Asym {
		resolvedPath := GlobalContext.Engine.ResolveKeyPath(nil, keyPath, "MAKNOON_PRIVATE_KEY")
		if resolvedPath == "" {
			return nil, nil, nil, fmt.Errorf("private key required via -k or MAKNOON_PRIVATE_KEY")
		}

		priv, err := GlobalContext.Engine.LoadPrivateKey(nil, resolvedPath, password, "", isStdin)
		if err != nil {
			return nil, nil, nil, err
		}
		return password, nil, priv, nil
	}

	// V2 symmetric (MAK2) — same passphrase resolution as V1 symmetric (MAKN).
	if magic == crypto.MagicHeaderV2Sym {
		if len(password) == 0 {
			var err error
			password, _, err = getPassphrase("Enter passphrase: ")
			if err != nil {
				return nil, nil, nil, err
			}
		}
		return password, password, nil, nil
	}

	return nil, nil, nil, fmt.Errorf("unsupported or invalid maknoon file header: %s", magic)
}
