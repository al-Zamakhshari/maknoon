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

	cmd := &cobra.Command{
		Use:   "decrypt [file]",
		Short: "Decrypt a .makn file or directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			inputFile := args[0]
			in, err := os.Open(inputFile)
			if err != nil {
				return fmt.Errorf("failed to open input file: %w", err)
			}
			defer in.Close()

			info, err := in.Stat()
			if err != nil {
				return err
			}

			// 1. Peek at the header to determine encryption type and flags
			header := make([]byte, 6)
			if _, err := io.ReadFull(in, header); err != nil {
				return fmt.Errorf("failed to read file header: %w", err)
			}
			in.Seek(0, 0)

			magic := string(header[:4])
			flags := header[5]

			// 2. Handle Passphrase/Identity logic
			password, finalKey, err := resolveDecryptionKey(magic, passphrase, keyPath, useFido2)
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
			fmt.Printf("Decrypting '%s'...\n", inputFile)

			pr, pw := io.Pipe()
			bar := progressbar.DefaultBytes(info.Size(), "restoring")
			proxyIn := io.TeeReader(in, bar)

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

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path or directory")
	cmd.Flags().StringVarP(&keyPath, "private-key", "k", "", "Path to your private key")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase for decryption")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "j", 0, "Number of parallel workers (0 for auto)")
	cmd.Flags().BoolVarP(&useFido2, "fido2", "f", false, "Use FIDO2 security key for authentication")
	return cmd
}

func resolveDecryptionKey(magic, manualPass, keyPath string, useFido2 bool) ([]byte, []byte, error) {
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
		return resolveAsymmetricKey(password, keyPath)
	}

	return nil, nil, fmt.Errorf("unsupported or invalid maknoon file header: %s", magic)
}

func resolveAsymmetricKey(password []byte, keyPath string) ([]byte, []byte, error) {
	resolvedPath := crypto.ResolveKeyPath(keyPath)
	keyBytes, err := os.ReadFile(resolvedPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %w", err)
	}

	if len(keyBytes) > 4 && string(keyBytes[:4]) == crypto.MagicHeader {
		// Handle FIDO2 or Passphrase unlocking
		password, err = unlockPrivateKey(password, resolvedPath, keyBytes)
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

func unlockPrivateKey(password []byte, resolvedPath string, keyBytes []byte) ([]byte, error) {
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
	if outPath == "" {
		if strings.HasSuffix(inputFile, ".makn") {
			outPath = strings.TrimSuffix(inputFile, ".makn")
		} else {
			outPath = inputFile + ".dec"
		}
	}
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, decryptedReader)
	return err
}
