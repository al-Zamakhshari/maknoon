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
	"github.com/username/maknoon/pkg/crypto"
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

			// Determine passphrase
			var password []byte
			if passphrase != "" {
				password = []byte(passphrase)
			} else if envPass := os.Getenv("MAKNOON_PASSPHRASE"); envPass != "" {
				password = []byte(envPass)
			}

			// Peek at the header to determine flags
			header := make([]byte, 6)
			if _, err := io.ReadFull(in, header); err != nil {
				return fmt.Errorf("failed to read file header: %w", err)
			}
			if _, err := in.Seek(0, 0); err != nil {
				return fmt.Errorf("failed to reset file pointer: %w", err)
			}

			magic := string(header[:4])
			flags := header[5]
			
			pr, pw := io.Pipe()
			bar := progressbar.DefaultBytes(info.Size(), "restoring")

			// Start decryption in a goroutine
			go func() {
				var dErr error
				if magic == crypto.MagicHeader {
					if len(password) == 0 {
						fmt.Print("Enter passphrase: ")
						p, _ := term.ReadPassword(int(os.Stdin.Fd()))
						fmt.Println()
						password = p
					}
					_, dErr = crypto.DecryptStream(io.TeeReader(in, bar), pw, password)
				} else if magic == crypto.MagicHeaderAsym {
					resolvedPath := resolveKeyPath(keyPath)
					privKeyBytes, err := os.ReadFile(resolvedPath)
					if err != nil {
						pw.CloseWithError(err)
						return
					}
					// Auto-unlock private key
					if len(privKeyBytes) > 4 && string(privKeyBytes[:4]) == crypto.MagicHeader {
						privKeyPassword := password
						if len(privKeyPassword) == 0 {
							fmt.Print("Enter passphrase to unlock your private key: ")
							p, _ := term.ReadPassword(int(os.Stdin.Fd()))
							fmt.Println()
							privKeyPassword = p
						}
						var unlockedKey bytes.Buffer
						crypto.DecryptStream(bytes.NewReader(privKeyBytes), &unlockedKey, privKeyPassword)
						privKeyBytes = unlockedKey.Bytes()
					}
					_, dErr = crypto.DecryptStreamWithPrivateKey(io.TeeReader(in, bar), pw, privKeyBytes)
				}
				pw.CloseWithError(dErr)
			}()

			// Handle Decompression
			var decryptedReader io.Reader = pr
			if flags&crypto.FlagCompress != 0 {
				zr, err := zstd.NewReader(pr)
				if err != nil { return err }
				defer zr.Close()
				decryptedReader = zr
			}

			// Handle Output/Extraction
			if flags&crypto.FlagArchive != 0 {
				if err := crypto.ExtractArchive(decryptedReader, output); err != nil {
					return err
				}
			} else {
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
				io.Copy(out, decryptedReader)
			}

			fmt.Println("\nDecryption successful!")
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path or directory")
	cmd.Flags().StringVarP(&keyPath, "private-key", "k", "", "Path to your private key")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase for decryption")
	return cmd
}
