package commands

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
			if err != nil {
				return err
			}

			// Peek at the header to determine encryption type
			header := make([]byte, 4)
			if _, err := io.ReadFull(in, header); err != nil {
				return fmt.Errorf("failed to read file header: %w", err)
			}
			if _, err := in.Seek(0, 0); err != nil {
				return fmt.Errorf("failed to reset file pointer: %w", err)
			}

			// Prepare the output destination (will be used if it's a single file)
			outPath := output
			if outPath == "" {
				if strings.HasSuffix(inputFile, ".makn") {
					outPath = strings.TrimSuffix(inputFile, ".makn")
				} else {
					outPath = inputFile + ".dec"
				}
			}

			// logic to handle standard file writing or directory extraction
			handleOutput := func(flags byte, r io.Reader) error {
				if flags == crypto.FlagArchive {
					// Directory Extraction
					tr := tar.NewReader(r)
					for {
						header, err := tr.Next()
						if err == io.EOF { break }
						if err != nil { return err }

						target := header.Name
						// If user provided a specific output dir, use it
						if output != "" {
							// Strip the original root folder and prepend output dir
							parts := strings.Split(header.Name, string(os.PathSeparator))
							if len(parts) > 1 {
								target = filepath.Join(output, filepath.Join(parts[1:]...))
							} else {
								target = output
							}
						}

						switch header.Typeflag {
						case tar.TypeDir:
							if err := os.MkdirAll(target, 0755); err != nil { return err }
						case tar.TypeReg:
							if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil { return err }
							f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
							if err != nil { return err }
							if _, err := io.Copy(f, tr); err != nil {
								f.Close()
								return err
							}
							f.Close()
						}
					}
					return nil
				} else {
					// Single File
					if _, err := os.Stat(outPath); err == nil {
						return fmt.Errorf("output file '%s' already exists", outPath)
					}
					out, err := os.Create(outPath)
					if err != nil { return err }
					defer out.Close()
					_, err = io.Copy(out, r)
					return err
				}
			}

			magic := string(header)
			switch magic {
			case crypto.MagicHeader:
				fmt.Print("Enter passphrase: ")
				password, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil { return err }
				defer func() {
					for i := range password { password[i] = 0 }
				}()

				fmt.Printf("Decrypting '%s'...\n", inputFile)
				
				bar := progressbar.DefaultBytes(info.Size(), "restoring")
				pr, pw := io.Pipe()
				var decryptErr error
				var flags byte
				go func() {
					flags, decryptErr = crypto.DecryptStream(io.TeeReader(in, bar), pw, password)
					pw.Close()
				}()

				if err := handleOutput(flags, pr); err != nil { return err }
				return decryptErr

			case crypto.MagicHeaderAsym:
				if keyPath == "" {
					return fmt.Errorf("file requires a private key for decryption (use --key)")
				}
				privKeyBytes, err := os.ReadFile(keyPath)
				if err != nil { return err }
				defer func() {
					for i := range privKeyBytes { privKeyBytes[i] = 0 }
				}()

				if len(privKeyBytes) > 4 && string(privKeyBytes[:4]) == crypto.MagicHeader {
					fmt.Print("Enter passphrase to unlock your private key: ")
					privKeyPass, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil { return err }
					defer func() {
						for i := range privKeyPass { privKeyPass[i] = 0 }
					}()
					var unlockedKey bytes.Buffer
					if _, err := crypto.DecryptStream(bytes.NewReader(privKeyBytes), &unlockedKey, privKeyPass); err != nil {
						return fmt.Errorf("failed to unlock private key: %w", err)
					}
					privKeyBytes = unlockedKey.Bytes()
				}

				fmt.Printf("Decrypting '%s' using private key '%s'...\n", inputFile, keyPath)
				
				bar := progressbar.DefaultBytes(info.Size(), "restoring")
				pr, pw := io.Pipe()
				var decryptErr error
				var flags byte
				go func() {
					flags, decryptErr = crypto.DecryptStreamWithPrivateKey(io.TeeReader(in, bar), pw, privKeyBytes)
					pw.Close()
				}()

				if err := handleOutput(flags, pr); err != nil { return err }
				return decryptErr

			default:
				return fmt.Errorf("unsupported or invalid maknoon file header: %s", magic)
			}
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", "Path to your private key for asymmetric decryption")
	return cmd
}
