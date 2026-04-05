package commands

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/a-khallaf/maknoon/pkg/crypto"
	"golang.org/x/term"
)

func DecryptCmd() *cobra.Command {
	var output string
	var keyPath string
	var passphrase string

	cmd := &cobra.Command{
		Use:   "decrypt [file]",
		Short: "Decrypt a .makn file or directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			inputFile := args[0]
			in, err := os.Open(inputFile)
			if err != nil {
				return fmt.Errorf("failed to open input file: %w", err)
			}
			defer in.Close()

			info, err := in.Stat()
			if err != nil { return err }

			password := getPassphrase(passphrase)

			// Peek at the header to determine flags
			header := make([]byte, 6)
			if _, err := io.ReadFull(in, header); err != nil {
				return fmt.Errorf("failed to read file header: %w", err)
			}
			in.Seek(0, 0)

			magic := string(header[:4])
			flags := header[5]
			
			pr, pw := io.Pipe()
			bar := progressbar.DefaultBytes(info.Size(), "restoring")

			go func() {
				var dErr error
				if magic == crypto.MagicHeader {
					password, dErr = ensurePassword(password)
					if dErr == nil {
						_, dErr = crypto.DecryptStream(io.TeeReader(in, bar), pw, password)
					}
				} else if magic == crypto.MagicHeaderAsym {
					dErr = handleAsymmetricDecryption(in, bar, pw, keyPath, password)
				} else {
					dErr = fmt.Errorf("unsupported or invalid maknoon file header: %s", magic)
				}
				pw.CloseWithError(dErr)
			}()

			return finalizeDecryption(pr, flags, output, inputFile)
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path or directory")
	cmd.Flags().StringVarP(&keyPath, "private-key", "k", "", "Path to your private key")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase for decryption")
	return cmd
}

func getPassphrase(manual string) []byte {
	if manual != "" {
		return []byte(manual)
	}
	if env := os.Getenv("MAKNOON_PASSPHRASE"); env != "" {
		return []byte(env)
	}
	return nil
}

func ensurePassword(p []byte) ([]byte, error) {
	if len(p) > 0 {
		return p, nil
	}
	fmt.Print("Enter passphrase: ")
	res, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return res, err
}

func handleAsymmetricDecryption(in io.Reader, bar *progressbar.ProgressBar, pw *io.PipeWriter, keyPath string, password []byte) error {
	resolvedPath := crypto.ResolveKeyPath(keyPath)
	privKeyBytes, err := os.ReadFile(resolvedPath)
	if err != nil { return err }

	if len(privKeyBytes) > 4 && string(privKeyBytes[:4]) == crypto.MagicHeader {
		privKeyPassword, err := ensurePassword(password)
		if err != nil { return err }
		
		var unlockedKey bytes.Buffer
		if _, err := crypto.DecryptStream(bytes.NewReader(privKeyBytes), &unlockedKey, privKeyPassword); err != nil {
			return fmt.Errorf("failed to unlock private key: %w", err)
		}
		privKeyBytes = unlockedKey.Bytes()
		defer crypto.SafeClear(privKeyBytes)
	}
	_, err = crypto.DecryptStreamWithPrivateKey(io.TeeReader(in, bar), pw, privKeyBytes)
	return err
}

func finalizeDecryption(pr io.Reader, flags byte, output, inputFile string) error {
	var decryptedReader io.Reader = pr
	if flags&crypto.FlagCompress != 0 {
		zr, err := zstd.NewReader(pr)
		if err != nil { return err }
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
	if err != nil { return err }
	defer out.Close()
	_, err = io.Copy(out, decryptedReader)
	return err
}
