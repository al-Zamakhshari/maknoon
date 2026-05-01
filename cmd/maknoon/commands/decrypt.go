package commands

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
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
	var concurrency int
	var useFido2 bool
	var quiet bool
	var verbose bool
	var profileFile string
	var overwrite bool
	var stealth bool
	var tofu bool

	cmd := &cobra.Command{
		Use:   "decrypt [file]",
		Short: "Decrypt a .makn file or directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			inputFile := args[0]
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
				if keyPath != "" || useFido2 || viper.GetString("private_key") != "" {
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
				flags = header[5]
			}

			// 2. Handle Passphrase/Identity logic
			password, finalKey, finalPriv, err := resolveDecryptionKey(magic, passphrase, keyPath, useFido2, inputFile == "-")
			if err != nil {
				p.RenderError(err)
				return err
			}

			// 3. Resolve optional sender public key for integrated verification
			var senderKey []byte
			if flags&crypto.FlagSigned != 0 {
				resolvedSenderPath := crypto.ResolveKeyPath(senderKeyPath, "MAKNOON_PUBLIC_KEY")
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
	cmd.Flags().IntVarP(&concurrency, "concurrency", "j", 0, "Number of parallel workers (0 for auto)")
	cmd.Flags().BoolVarP(&useFido2, "fido2", "f", false, "Use FIDO2 security key for authentication")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress bars and informational messages")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Enable internal pipeline tracing (slog)")
	cmd.Flags().BoolVar(&stealth, "stealth", false, "Enable fingerprint resistance (headerless)")
	cmd.Flags().BoolVar(&tofu, "trust-on-first-use", false, "Automatically add unknown signers to contacts")
	cmd.Flags().StringVar(&profileFile, "profile-file", "", "Path to a custom profile JSON file")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing files")
	return cmd
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

func resolveDecryptionKey(magic, manualPass, keyPath string, useFido2 bool, isStdin bool) ([]byte, []byte, []byte, error) {
	var password []byte
	if manualPass != "" {
		password = []byte(manualPass)
	} else if env := viper.GetString("passphrase"); env != "" {
		password = []byte(env)
	}

	if magic == crypto.MagicHeader {
		if useFido2 {
			return nil, nil, nil, fmt.Errorf("FIDO2-backed symmetric encryption is currently only supported via the 'vault' command")
		}
		if len(password) == 0 {
			var err error
			password, _, err = getPassphrase("Enter passphrase: ")
			if err != nil {
				return nil, nil, nil, err
			}
		}
		return password, password, nil, nil
	}

	if magic == crypto.MagicHeaderAsym {
		resolvedPath := GlobalContext.Engine.ResolveKeyPath(nil, keyPath, "MAKNOON_PRIVATE_KEY")
		if resolvedPath == "" {
			return nil, nil, nil, fmt.Errorf("private key required via -k or MAKNOON_PRIVATE_KEY")
		}

		// Check for FIDO2 and get PIN if needed
		var pin string
		if _, err := os.Stat(strings.TrimSuffix(resolvedPath, ".key") + ".fido2"); err == nil {
			var err2 error
			pin, err2 = getPIN()
			if err2 != nil {
				return nil, nil, nil, err2
			}
		}

		priv, err := GlobalContext.Engine.LoadPrivateKey(nil, resolvedPath, password, pin, isStdin)
		if err != nil {
			return nil, nil, nil, err
		}
		return password, nil, priv, nil
	}

	return nil, nil, nil, fmt.Errorf("unsupported or invalid maknoon file header: %s", magic)
}
