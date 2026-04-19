package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/klauspost/compress/zstd"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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

	cmd := &cobra.Command{
		Use:   "decrypt [file]",
		Short: "Decrypt a .makn file or directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inputFile := args[0]
			in, inputName, totalSize, err := resolveDecryptInput(inputFile)
			if err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}
			if f, ok := in.(*os.File); ok {
				defer func() { _ = f.Close() }()
			}

			if profileFile != "" {
				if err := loadCustomProfile(profileFile, nil); err != nil {
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
					return nil
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
					return nil
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

			// 5. Initialize the Progress Bar and Pipe
			if !quiet && outPath != "-" {
				fmt.Printf("Decrypting '%s'...\n", inputName)
			}

			pr, pw := io.Pipe()
			proxyIn := fullIn
			if !quiet && totalSize > 0 && outPath != "-" {
				bar := progressbar.DefaultBytes(totalSize, "restoring")
				proxyIn = io.TeeReader(fullIn, bar)
			}

			go func() {
				var dErr error
				var f byte
				if magic == crypto.MagicHeader {
					f, dErr = crypto.DecryptStream(proxyIn, pw, finalKey, concurrency, stealth)
				} else {
					f, dErr = crypto.DecryptStreamWithPrivateKeyAndVerifier(proxyIn, pw, finalKey, senderKey, concurrency, stealth)
				}
				_ = f
				_ = pw.CloseWithError(dErr)
			}()

			if outPath == "-" {
				// If we are outputting to stdout, we MUST send JSON status to stderr
				// to avoid corrupting the raw data stream.
				oldWriter := JSONWriter
				JSONWriter = os.Stderr
				defer func() { JSONWriter = oldWriter }()
			}

			if err := finalizeDecryption(pr, flags, outPath); err != nil {
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

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path or directory (use - for stdout)")
	cmd.Flags().StringVarP(&keyPath, "private-key", "k", "", "Path to your private key")
	cmd.Flags().StringVar(&senderKeyPath, "sender-key", "", "Path to the sender's public key (required for signed files)")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase for decryption")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "j", 0, "Number of parallel workers (0 for auto)")
	cmd.Flags().BoolVarP(&useFido2, "fido2", "f", false, "Use FIDO2 security key for authentication")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress bars and informational messages")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Enable internal pipeline tracing (slog)")
	cmd.Flags().BoolVar(&stealth, "stealth", false, "Enable fingerprint resistance (headerless)")
	cmd.Flags().StringVar(&profileFile, "profile-file", "", "Path to a custom profile JSON file")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing files")
	return cmd
}

func resolveDecryptInput(path string) (io.Reader, string, int64, error) {
	if path == "-" {
		return os.Stdin, "stdin", -1, nil
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
	if output == "-" {
		return "-", nil
	}
	if output != "" {
		return output, nil
	}
	if inputFile == "-" {
		return "", fmt.Errorf("output path required when reading from stdin (use -o)")
	}

	if flags&crypto.FlagArchive != 0 {
		return ".", nil
	}

	if strings.HasSuffix(inputFile, ".makn") {
		return strings.TrimSuffix(inputFile, ".makn"), nil
	}
	return inputFile + ".dec", nil
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
			if isStdin {
				return nil, nil, fmt.Errorf("passphrase required via MAKNOON_PASSPHRASE or -s when reading from stdin")
			}
			fmt.Print("Enter passphrase: ")
			p, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return nil, nil, err
			}
			password = p
		}
		return password, password, nil
	}

	if magic == crypto.MagicHeaderAsym {
		return resolveAsymmetricKey(password, keyPath, isStdin)
	}

	return nil, nil, fmt.Errorf("unsupported or invalid maknoon file header: %s", magic)
}

func resolveAsymmetricKey(password []byte, keyPath string, isStdin bool) ([]byte, []byte, error) {
	resolvedPath := crypto.ResolveKeyPath(keyPath, "MAKNOON_PRIVATE_KEY")
	if resolvedPath == "" && keyPath != "" {
		return nil, nil, fmt.Errorf("private key not found: %s", keyPath)
	}
	if resolvedPath == "" {
		return nil, nil, fmt.Errorf("private key required via -k or MAKNOON_PRIVATE_KEY")
	}

	keyBytes, err := os.ReadFile(resolvedPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %w", err)
	}

	if len(keyBytes) > 4 && string(keyBytes[:4]) == crypto.MagicHeader {
		var err error
		password, err = unlockPrivateKey(password, resolvedPath, isStdin)
		if err != nil {
			return nil, nil, err
		}

		var unlockedKey bytes.Buffer
		if _, err := crypto.DecryptStream(bytes.NewReader(keyBytes), &unlockedKey, password, 1, false); err != nil {
			return nil, nil, fmt.Errorf("failed to unlock private key: %w", err)
		}
		return password, unlockedKey.Bytes(), nil
	}

	return password, keyBytes, nil
}

func unlockPrivateKey(password []byte, resolvedPath string, isStdin bool) ([]byte, error) {
	fido2Path := strings.TrimSuffix(resolvedPath, ".key")
	fido2Path = strings.TrimSuffix(fido2Path, ".kem")
	fido2Path = strings.TrimSuffix(fido2Path, ".sig")
	fido2Path += ".fido2"

	if _, err := os.Stat(fido2Path); err == nil {
		raw, err := os.ReadFile(fido2Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read fido2 metadata: %w", err)
		}
		var meta crypto.Fido2Metadata
		if err := json.Unmarshal(raw, &meta); err != nil {
			return nil, fmt.Errorf("failed to unmarshal fido2 metadata: %w", err)
		}

		return crypto.Fido2Derive(meta.RPID, meta.CredentialID)
	}

	if len(password) == 0 {
		if isStdin {
			return nil, fmt.Errorf("passphrase required via MAKNOON_PASSPHRASE or -s to unlock private key when reading from stdin")
		}
		fmt.Print("Enter passphrase to unlock your private key: ")
		p, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, err
		}
		password = p
	}
	return password, nil
}

func finalizeDecryption(pr io.Reader, flags byte, outPath string) error {
	decryptedReader := pr
	if flags&crypto.FlagCompress != 0 {
		zr, err := zstd.NewReader(pr)
		if err != nil {
			return fmt.Errorf("failed to initialize zstd reader: %w", err)
		}
		defer zr.Close()
		decryptedReader = zr
	}

	if flags&crypto.FlagArchive != 0 {
		if err := crypto.ExtractArchive(decryptedReader, outPath); err != nil {
			return fmt.Errorf("failed to extract archive: %w", err)
		}
		return nil
	}

	var out io.Writer
	if outPath == "-" {
		out = os.Stdout
	} else {
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	if _, err := io.Copy(out, decryptedReader); err != nil {
		return fmt.Errorf("failed to write decrypted data: %w", err)
	}
	return nil
}
