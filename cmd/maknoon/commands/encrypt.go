package commands

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/username/maknoon/pkg/crypto"
	"golang.org/x/term"
)

func EncryptCmd() *cobra.Command {
	var output string
	var pubKeyPath string
	var passphrase string

	cmd := &cobra.Command{
		Use:   "encrypt [file/dir]",
		Short: "Encrypt a file or directory symmetrically or asymmetrically",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			inputPath := args[0]
			
			stat, err := os.Stat(inputPath)
			if err != nil {
				return fmt.Errorf("failed to access input path: %w", err)
			}

			outPath := output
			if outPath == "" {
				outPath = inputPath + ".makn"
			}
			out, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}
			defer out.Close()

			flags := crypto.FlagFile
			if stat.IsDir() {
				flags = crypto.FlagArchive
			}

			// Prepare the data source
			var reader io.Reader
			var totalSize int64

			if stat.IsDir() {
				// Archive Mode: Calculate total size for progress bar
				err = filepath.Walk(inputPath, func(_ string, info os.FileInfo, err error) error {
					if err != nil { return err }
					if !info.IsDir() {
						totalSize += info.Size()
					}
					return nil
				})
				if err != nil {
					return fmt.Errorf("failed to calculate directory size: %w", err)
				}

				// Create a pipe to stream tar data
				pr, pw := io.Pipe()
				reader = pr
				go func() {
					tw := tar.NewWriter(pw)
					err := filepath.Walk(inputPath, func(path string, info os.FileInfo, err error) error {
						if err != nil { return err }
						
						header, err := tar.FileInfoHeader(info, info.Name())
						if err != nil { return err }
						
						// Ensure the name in the tar is relative to the input folder
						rel, err := filepath.Rel(filepath.Dir(inputPath), path)
						if err != nil { return err }
						header.Name = rel

						if err := tw.WriteHeader(header); err != nil {
							return err
						}

						if !info.IsDir() {
							f, err := os.Open(path)
							if err != nil { return err }
							defer f.Close()
							_, err = io.Copy(tw, f)
							return err
						}
						return nil
					})
					tw.Close()
					pw.CloseWithError(err)
				}()
			} else {
				// Single File Mode
				f, err := os.Open(inputPath)
				if err != nil {
					return fmt.Errorf("failed to open input file: %w", err)
				}
				defer f.Close()
				reader = f
				totalSize = stat.Size()
			}

			// Asymmetric Mode (Public Key)
			if pubKeyPath != "" {
				pubKeyBytes, err := os.ReadFile(pubKeyPath)
				if err != nil {
					return fmt.Errorf("failed to read public key: %w", err)
				}
				fmt.Printf("Encrypting '%s' using public key '%s'...\n", inputPath, pubKeyPath)

				bar := progressbar.DefaultBytes(totalSize, "preserving")
				if err := crypto.EncryptStreamWithPublicKey(io.TeeReader(reader, bar), out, pubKeyBytes, flags); err != nil {
					return fmt.Errorf("encryption failed: %w", err)
				}
			} else {
				// Symmetric Mode (Passphrase)
				var password []byte
				
				// 1. Check Flag
				if passphrase != "" {
					password = []byte(passphrase)
				}
				
				// 2. Check Environment Variable
				if len(password) == 0 {
					if envPass := os.Getenv("MAKNOON_PASSPHRASE"); envPass != "" {
						password = []byte(envPass)
					}
				}

				// 3. Fallback to Interactive
				if len(password) == 0 {
					fmt.Print("Enter passphrase: ")
					p, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil {
						return err
					}
					password = p

					fmt.Print("Confirm passphrase: ")
					confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil {
						return err
					}
					defer func() {
						for i := range confirm {
							confirm[i] = 0
						}
					}()
					if string(password) != string(confirm) {
						return fmt.Errorf("passphrases do not match")
					}
				}

				defer func() {
					for i := range password {
						password[i] = 0
					}
				}()

				fmt.Printf("Encrypting '%s' using passphrase...\n", inputPath)

				bar := progressbar.DefaultBytes(totalSize, "preserving")
				if err := crypto.EncryptStream(io.TeeReader(reader, bar), out, password, flags); err != nil {
					return fmt.Errorf("encryption failed: %w", err)
				}
			}

			fmt.Println("\nEncryption successful! Data is now Maknoon (carefully preserved).")
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (default is input.makn)")
	cmd.Flags().StringVarP(&pubKeyPath, "pubkey", "p", "", "Path to the recipient's public key for asymmetric encryption")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase for symmetric encryption (Avoid for security!)")
	return cmd
}
