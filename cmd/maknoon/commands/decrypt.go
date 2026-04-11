package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/a-khallaf/maknoon/pkg/crypto"
	"github.com/klauspost/compress/zstd"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// DecryptCmd returns the cobra command for decrypting .makn files.
func DecryptCmd() *cobra.Command {
	var output string
	var keyPath string
	var passphrase string
	var concurrency int
	var useFido2 bool
	var quiet bool
	var profileFile string

	cmd := &cobra.Command{
		Use:   "decrypt [file]",
		Short: "Decrypt a .makn file or directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inputFile := args[0]
			var in io.Reader
			var inputName string
			var totalSize int64 = -1

			if inputFile == "-" {
				in = os.Stdin
				inputName = "stdin"
			} else {
				f, err := os.Open(inputFile)
				if err != nil {
					return fmt.Errorf("failed to open input file: %w", err)
				}
				defer f.Close()
				info, err := f.Stat()
				if err != nil {
					return err
				}
				totalSize = info.Size()
				in = f
				inputName = inputFile
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
			}

			// 1. Peek at the header to determine encryption type and flags
			// We need a way to peek at stdin if it's stdin.
			// Let's use a buffered reader or just read the first few bytes.
			header := make([]byte, 6)
			// If it's stdin, we might lose these 6 bytes from the stream if we're not careful.
			// Actually, we can just use io.MultiReader to put them back.
			if _, err := io.ReadFull(in, header); err != nil {
				return fmt.Errorf("failed to read file header: %w", err)
			}
			fullIn := io.MultiReader(bytes.NewReader(header), in)

			magic := string(header[:4])
			flags := header[5]

			// 2. Handle Passphrase/Identity logic
			password, finalKey, err := resolveDecryptionKey(magic, passphrase, keyPath, useFido2, inputFile == "-")
			if err != nil {
				return err
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

			// 3. Now that we have everything, initialize the Progress Bar and Pipe
			if !quiet && output != "-" {
				fmt.Printf("Decrypting '%s'...\n", inputName)
			}

			pr, pw := io.Pipe()
			var proxyIn io.Reader = fullIn
			if !quiet && totalSize > 0 && output != "-" {
				bar := progressbar.DefaultBytes(totalSize, "restoring")
				proxyIn = io.TeeReader(fullIn, bar)
			}

			go func() {
				var dErr error
				if magic == crypto.MagicHeader {
					_, dErr = crypto.DecryptStream(proxyIn, pw, finalKey, concurrency)
				} else {
					_, dErr = crypto.DecryptStreamWithPrivateKey(proxyIn, pw, finalKey, concurrency)
				}
				pw.CloseWithError(dErr)
			}()

			return finalizeDecryption(pr, flags, output, inputFile)
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path or directory (use - for stdout)")
	cmd.Flags().StringVarP(&keyPath, "private-key", "k", "", "Path to your private key")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase for decryption")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "j", 0, "Number of parallel workers (0 for auto)")
	cmd.Flags().BoolVarP(&useFido2, "fido2", "f", false, "Use FIDO2 security key for authentication")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress progress bars and informational messages")
	cmd.Flags().StringVar(&profileFile, "profile-file", "", "Path to a custom profile JSON file")
	return cmd
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
		// Handle FIDO2 or Passphrase unlocking
		password, err = unlockPrivateKey(password, resolvedPath, keyBytes, isStdin)
		if err != nil {
			return nil, nil, err
		}

		var unlockedKey bytes.Buffer
		if _, err := crypto.DecryptStream(bytes.NewReader(keyBytes), &unlockedKey, password, 1); err != nil {
			return nil, nil, fmt.Errorf("failed to unlock private key: %w", err)
		}
		return password, unlockedKey.Bytes(), nil
	}

	return password, keyBytes, nil
}

func unlockPrivateKey(password []byte, resolvedPath string, keyBytes []byte, isStdin bool) ([]byte, error) {
	// Check for companion FIDO2 file
	fido2Path := strings.TrimSuffix(resolvedPath, ".key")
	fido2Path = strings.TrimSuffix(fido2Path, ".kem")
	fido2Path = strings.TrimSuffix(fido2Path, ".sig")
	fido2Path += ".fido2"

	if _, err := os.Stat(fido2Path); err == nil {
		raw, _ := os.ReadFile(fido2Path)
		var meta crypto.Fido2Metadata
		json.Unmarshal(raw, &meta)

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

func finalizeDecryption(pr io.Reader, flags byte, output, inputFile string) error {
	decryptedReader := pr
	if flags&crypto.FlagCompress != 0 {
		zr, err := zstd.NewReader(pr)
		if err != nil {
			return err
		}
		defer zr.Close()
		decryptedReader = zr
	}

	if flags&crypto.FlagArchive != 0 {
		return crypto.ExtractArchive(decryptedReader, output)
	}

	outPath := output
	var out io.Writer
	if outPath == "-" {
		out = os.Stdout
	} else {
		if outPath == "" {
			if inputFile == "-" {
				return fmt.Errorf("output path required when reading from stdin (use -o)")
			}
			if strings.HasSuffix(inputFile, ".makn") {
				outPath = strings.TrimSuffix(inputFile, ".makn")
			} else {
				outPath = inputFile + ".dec"
			}
		}
		f, err := os.Create(outPath)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}

	_, err := io.Copy(out, decryptedReader)
	return err
}
