package commands

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/username/maknoon/pkg/crypto"
	"golang.org/x/term"
)

func DecryptCmd() *cobra.Command {
	var output string
	var keyPath string

	cmd := &cobra.Command{
		Use:   "decrypt [file]",
		Short: "Decrypt a .makn file using a passphrase or private key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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

			// Peek at the header to determine encryption type
			header := make([]byte, 4)
			if _, err := io.ReadFull(in, header); err != nil {
				return fmt.Errorf("failed to read file header: %w", err)
			}
			// Reset file pointer
			if _, err := in.Seek(0, 0); err != nil {
				return fmt.Errorf("failed to reset file pointer: %w", err)
			}

			outPath := output
			if outPath == "" {
				if strings.HasSuffix(inputFile, ".makn") {
					outPath = strings.TrimSuffix(inputFile, ".makn")
				} else {
					outPath = inputFile + ".dec"
				}
			}

			if _, err := os.Stat(outPath); err == nil {
				return fmt.Errorf("output file '%s' already exists", outPath)
			}

			out, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}
			defer out.Close()

			magic := string(header)
			switch magic {
			case crypto.MagicHeader:
				fmt.Print("Enter passphrase: ")
				password, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					return err
				}
				defer func() {
					for i := range password {
						password[i] = 0
					}
				}()

				fmt.Printf("Decrypting '%s' using passphrase...\n", inputFile)
				
				bar := progressbar.DefaultBytes(info.Size(), "restoring")
				if err := crypto.DecryptStream(io.TeeReader(in, bar), out, password); err != nil {
					os.Remove(outPath)
					return fmt.Errorf("decryption failed: %w", err)
				}

			case crypto.MagicHeaderAsym:
				if keyPath == "" {
					os.Remove(outPath)
					return fmt.Errorf("file requires a private key for decryption (use --key)")
				}
				privKeyBytes, err := os.ReadFile(keyPath)
				if err != nil {
					os.Remove(outPath)
					return fmt.Errorf("failed to read private key: %w", err)
				}
				defer func() {
					for i := range privKeyBytes {
						privKeyBytes[i] = 0
					}
				}()

				// Check if the private key itself is encrypted with Maknoon (Symmetric)
				if len(privKeyBytes) > 4 && string(privKeyBytes[:4]) == crypto.MagicHeader {
					fmt.Print("Enter passphrase to unlock your private key: ")
					privKeyPass, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil {
						os.Remove(outPath)
						return err
					}
					defer func() {
						for i := range privKeyPass {
							privKeyPass[i] = 0
						}
					}()
					var unlockedKey bytes.Buffer
					if err := crypto.DecryptStream(bytes.NewReader(privKeyBytes), &unlockedKey, privKeyPass); err != nil {
						os.Remove(outPath)
						return fmt.Errorf("failed to unlock private key: %w", err)
					}
					privKeyBytes = unlockedKey.Bytes()
				}

				fmt.Printf("Decrypting '%s' using private key '%s'...\n", inputFile, keyPath)
				
				bar := progressbar.DefaultBytes(info.Size(), "restoring")
				if err := crypto.DecryptStreamWithPrivateKey(io.TeeReader(in, bar), out, privKeyBytes); err != nil {
					os.Remove(outPath)
					return fmt.Errorf("decryption failed: %w", err)
				}
			default:
				os.Remove(outPath)
				return fmt.Errorf("unsupported or invalid maknoon file header: %s", magic)
			}

			fmt.Println("\nDecryption successful! The data has been carefully restored.")
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", "Path to your private key for asymmetric decryption")
	return cmd
}
