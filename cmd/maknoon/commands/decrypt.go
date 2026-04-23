package commands

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
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
		RunE: func(_ *cobra.Command, args []string) error {
			inputFile := args[0]
			in, _, totalSize, err := resolveDecryptInput(inputFile)
			if err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return err
				}
				return err
			}
			if f, ok := in.(*os.File); ok {
				defer func() { _ = f.Close() }()
			}

			if profileFile != "" {
				if _, err := GlobalContext.Engine.LoadCustomProfile(profileFile); err != nil {
					if JSONOutput {
						printErrorJSON(err)
						return nil
					}
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
					err := fmt.Errorf("failed to read stealth header: %w", err)
					if JSONOutput {
						printErrorJSON(err)
						return nil
					}
					return err
				}
				fullIn = io.MultiReader(bytes.NewReader(header), in)
				flags = header[1]

				// Infer magic based on provided decryption params
				if keyPath != "" || useFido2 || os.Getenv("MAKNOON_PRIVATE_KEY") != "" {
					magic = crypto.MagicHeaderAsym
				} else {
					magic = crypto.MagicHeader
				}
				if verbose {
					fmt.Printf("DEBUG: Stealth mode active. Inferred Magic=%s Flags=0x%02x\n", magic, flags)
				}
			} else {
				header := make([]byte, 6)
				if _, err := io.ReadFull(in, header); err != nil {
					err := fmt.Errorf("failed to read file header: %w", err)
					if JSONOutput {
						printErrorJSON(err)
						return nil
					}
					return err
				}
				fullIn = io.MultiReader(bytes.NewReader(header), in)

				magic = string(header[:4])
				flags = header[5]
				if verbose {
					fmt.Printf("DEBUG: Magic=%s Flags=0x%02x\n", magic, flags)
				}
			}

			// 2. Handle Passphrase/Identity logic
			password, finalKey, err := resolveDecryptionKey(magic, passphrase, keyPath, useFido2, inputFile == "-")
			if err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return err
				}
				return err
			}

			// 3. Resolve optional sender public key for integrated verification
			var senderKey []byte
			if flags&crypto.FlagSigned != 0 {
				resolvedSenderPath := crypto.ResolveKeyPath(senderKeyPath, "MAKNOON_PUBLIC_KEY")
				if resolvedSenderPath == "" {
					err := fmt.Errorf("file has integrated signature but sender public key not provided (use --sender-key)")
					if JSONOutput {
						printErrorJSON(err)
						return nil
					}
					return err
				}
				sk, err := os.ReadFile(resolvedSenderPath)
				if err != nil {
					err := fmt.Errorf("failed to read sender public key: %w", err)
					if JSONOutput {
						printErrorJSON(err)
						return nil
					}
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
				}
			}()

			// 4. Prepare output path and check existence
			outPath, err := resolveDecryptionOutputPath(output, inputFile, flags)
			if err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return err
				}
				return err
			}

			if outPath != "-" && !overwrite {
				if _, err := os.Stat(outPath); err == nil {
					err := fmt.Errorf("output path already exists: %s (use --overwrite to bypass)", outPath)
					if JSONOutput {
						printErrorJSON(err)
						return nil
					}
					return err
				}
			}

			// 5. Initialize the Event Stream and Telemetry
			events := make(chan crypto.EngineEvent, 100)
			opts := crypto.Options{
				Passphrase:  finalKey,
				PublicKey:   senderKey,
				Concurrency: concurrency,
				Stealth:     stealth,
				TotalSize:   totalSize,
				EventStream: events,
				Verbose:     verbose,
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

			_, err = GlobalContext.Engine.Unprotect(fullIn, nil, outPath, opts)
			close(events)
			<-done

			if err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return err
				}
				return err
			}

			// 6. Handle Trust Evidence and TOFU
			var trustInfo map[string]interface{}
			if senderKey != nil {
				gid := fmt.Sprintf("mk1_%x", crypto.Sha256Sum(senderKey)[:16])
				isTrusted := false
				var existingContact *crypto.Contact

				cm, err := crypto.NewContactManager()
				if err == nil {
					// We search by GID or we could search by fingerprint.
					contacts, _ := cm.List()
					for _, c := range contacts {
						if bytes.Equal(c.KEMPubKey, senderKey) || bytes.Equal(c.SIGPubKey, senderKey) {
							isTrusted = true
							existingContact = c
							break
						}
					}

					if !isTrusted && tofu {
						// Auto-learn contact
						newContact := &crypto.Contact{
							Petname:   "@" + gid[:12],
							SIGPubKey: senderKey,
							AddedAt:   time.Now(),
							Notes:     "Auto-learned via TOFU",
						}
						_ = cm.Add(newContact)
						isTrusted = true
						existingContact = newContact
					}
					cm.Close()
				}

				trustInfo = map[string]interface{}{
					"gid":        gid,
					"is_trusted": isTrusted,
				}
				if existingContact != nil {
					trustInfo["petname"] = existingContact.Petname
				}
			}

			if JSONOutput {
				res := map[string]interface{}{
					"status": "success",
					"output": outPath,
				}
				if trustInfo != nil {
					res["signed_by"] = trustInfo
				}
				printJSON(res)
			} else if trustInfo != nil {
				status := "UNKNOWN (Untrusted)"
				if trustInfo["is_trusted"].(bool) {
					status = fmt.Sprintf("TRUSTED (%s)", trustInfo["petname"])
				}
				fmt.Printf("✔ Successfully verified signature from: %s [%s]\n", trustInfo["gid"], status)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path or directory (use - for stdout)")
	cmd.Flags().StringVarP(&keyPath, "private-key", "k", "", "Path to your private key")
	cmd.Flags().StringVar(&senderKeyPath, "sender-key", "", "Path to the sender's public key (required for signed files)")
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

func resolveDecryptionKey(magic, manualPass, keyPath string, useFido2 bool, isStdin bool) ([]byte, []byte, error) {
	var password []byte
	if manualPass != "" {
		password = []byte(manualPass)
	} else if env := os.Getenv("MAKNOON_PASSPHRASE"); env != "" {
		password = []byte(env)
	}

	if magic == crypto.MagicHeader {
		if useFido2 {
			return nil, nil, fmt.Errorf("FIDO2-backed symmetric encryption is currently only supported via the 'vault' command")
		}
		if len(password) == 0 {
			var err error
			password, _, err = getPassphrase("Enter passphrase: ")
			if err != nil {
				return nil, nil, err
			}
		}
		return password, password, nil
	}

	if magic == crypto.MagicHeaderAsym {
		m := crypto.NewIdentityManager()
		resolvedPath := m.ResolveKeyPath(keyPath, "MAKNOON_PRIVATE_KEY")
		if resolvedPath == "" {
			return nil, nil, fmt.Errorf("private key required via -k or MAKNOON_PRIVATE_KEY")
		}

		// Check for FIDO2 and get PIN if needed
		var pin string
		if _, err := os.Stat(strings.TrimSuffix(resolvedPath, ".key") + ".fido2"); err == nil {
			var err2 error
			pin, err2 = getPIN()
			if err2 != nil {
				return nil, nil, err2
			}
		}

		priv, err := m.LoadPrivateKey(resolvedPath, password, pin, isStdin)
		if err != nil {
			return nil, nil, err
		}
		return password, priv, nil
	}

	return nil, nil, fmt.Errorf("unsupported or invalid maknoon file header: %s", magic)
}
